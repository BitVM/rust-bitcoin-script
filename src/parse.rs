use bitcoin::{blockdata::opcodes::Opcode, opcodes::all::OP_RESERVED};
use proc_macro2::{
    Delimiter, Span, TokenStream,
    TokenTree::{self, *},
};
use quote::quote;
use std::iter::Peekable;
use std::str::FromStr;

#[derive(Debug)]
pub enum Syntax {
    Opcode(Opcode),
    Escape(TokenStream),
    Bytes(Vec<u8>),
    Int(i64),
}

macro_rules! emit_error {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::emit_error!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);

        #[allow(unreachable_code)]
        {
            panic!();
        }
    }}
}

macro_rules! abort {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::abort!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);
    }}
}

pub fn parse(tokens: TokenStream) -> Vec<(Syntax, Span)> {
    let mut tokens = tokens.into_iter().peekable();
    let mut syntax = Vec::with_capacity(2048);

    while let Some(token) = tokens.next() {
        let token_str = token.to_string();
        syntax.push(match (&token, token_str.as_ref()) {
            // Wrap for loops such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "for" => parse_for_loop(token, &mut tokens),
            // Wrap if-else statements such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "if" => parse_if(token, &mut tokens),
            // Replace DEBUG with OP_RESERVED
            (Ident(_), ident_str) if ident_str == "DEBUG" => {
                (Syntax::Opcode(OP_RESERVED), token.span())
            }

            // identifier, look up opcode
            (Ident(_), _) => {
                match Opcode::from_str(&token_str) {
                    Ok(opcode) => (Syntax::Opcode(opcode), token.span()),
                    // Not a native Bitcoin opcode
                    // Allow functions without arguments to be identified by just their name
                    _ => {
                        let span = token.span();
                        let mut pseudo_stream = TokenStream::from(token);
                        pseudo_stream.extend(TokenStream::from_str("()"));
                        (Syntax::Escape(pseudo_stream), span)
                    }
                }
            }

            (Group(inner), _) => {
                let escape = TokenStream::from(inner.stream().clone());
                (Syntax::Escape(escape), token.span())
            }

            // '<', start of escape (parse until first '>')
            (Punct(_), "<") => parse_escape(token, &mut tokens),

            // '~' start of escape (parse until the next '~') ignores '<' and '>'
            (Punct(_), "~") => parse_escape_extra(token, &mut tokens),

            // literal, push data (int or bytes)
            (Literal(_), _) => parse_data(token),

            // negative sign, parse negative int
            (Punct(_), "-") => parse_negative_int(token, &mut tokens),

            // anything else is invalid
            _ => abort!(token.span(), "unexpected token"),
        });
    }
    syntax
}

fn parse_if<T>(token: TokenTree, tokens: &mut Peekable<T>) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    // Use a Vec here to get rid of warnings when the variable is overwritten
    let mut escape = quote! {
        let mut script_var = Vec::with_capacity(256);
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(if_token) = tokens.next() {
        match if_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        script_var.extend_from_slice(script! {
                            #inner_block
                        }.as_bytes());
                    }
                });

                match tokens.peek() {
                    Some(else_token) if else_token.to_string().as_str() == "else" => continue,
                    _ => break,
                }
            }
            _ => {
                escape.extend(std::iter::once(if_token));
                continue;
            }
        };
    }
    escape = quote! {
        {
            #escape;
            bitcoin::script::ScriptBuf::from(script_var)
        }
    }
    .into();
    (Syntax::Escape(escape), token.span())
}

fn parse_for_loop<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = quote! {
        let mut script_var = vec![];
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(for_token) = tokens.next() {
        match for_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        let next_script = script !{
                            #inner_block
                        };
                        script_var.extend_from_slice(next_script.as_bytes());
                    }
                    bitcoin::script::ScriptBuf::from(script_var)
                });
                break;
            }
            _ => {
                escape.extend(std::iter::once(for_token));
                continue;
            }
        };
    }

    (Syntax::Escape(quote! { { #escape } }.into()), token.span())
}

fn parse_escape<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), ">") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_escape_extra<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), "~") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_data(token: TokenTree) -> (Syntax, Span) {
    if token.to_string().starts_with("0x") {
        if token
            .to_string()
            .strip_prefix("0x")
            .unwrap_or_else(|| unreachable!())
            .trim_start_matches('0')
            .len()
            <= 8
        {
            parse_hex_int(token)
        } else {
            parse_bytes(token)
        }
    } else {
        parse_int(token, false)
    }
}

fn parse_bytes(token: TokenTree) -> (Syntax, Span) {
    let hex_bytes = &token.to_string()[2..];
    let bytes = hex::decode(hex_bytes).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex literal ({})", err);
    });
    (Syntax::Bytes(bytes), token.span())
}

fn parse_hex_int(token: TokenTree) -> (Syntax, Span) {
    let token_str = &token.to_string()[2..];
    let n: u32 = u32::from_str_radix(token_str, 16).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex string ({})", err);
    });
    (Syntax::Int(n as i64), token.span())
}

fn parse_int(token: TokenTree, negative: bool) -> (Syntax, Span) {
    let token_str = token.to_string();
    let n: i64 = token_str.parse().unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid number literal ({})", err);
    });
    let n = if negative { n * -1 } else { n };
    (Syntax::Int(n), token.span())
}

fn parse_negative_int<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let fail = || {
        #[allow(unused_variables)]
        let span = token.span();
        emit_error!(
            span,
            "expected negative sign to be followed by number literal"
        );
    };

    let maybe_token = tokens.next();

    if let Some(token) = maybe_token {
        if let Literal(_) = token {
            parse_int(token, true)
        } else {
            fail()
        }
    } else {
        fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::opcodes::all as opcodes;
    use quote::quote;

    #[test]
    fn parse_empty() {
        assert!(parse(quote!()).is_empty());
    }

    #[test]
    #[should_panic(expected = "unexpected token")]
    fn parse_unexpected_token() {
        parse(quote!(OP_CHECKSIG &));
    }

    //#[test]
    //#[should_panic(expected = "unknown opcode \"A\"")]
    //fn parse_invalid_opcode() {
    //    parse(quote!(OP_CHECKSIG A B));
    //}

    #[test]
    fn parse_opcodes() {
        let syntax = parse(quote!(OP_CHECKSIG OP_HASH160));

        if let Syntax::Opcode(opcode) = syntax[0].0 {
            assert_eq!(opcode, opcodes::OP_CHECKSIG);
        } else {
            panic!();
        }

        if let Syntax::Opcode(opcode) = syntax[1].0 {
            assert_eq!(opcode, opcodes::OP_HASH160);
        } else {
            panic!();
        }
    }

    #[test]
    #[should_panic(expected = "unterminated escape")]
    fn parse_unterminated_escape() {
        parse(quote!(OP_CHECKSIG < abc));
    }

    #[test]
    fn parse_escape() {
        let syntax = parse(quote!(OP_CHECKSIG<abc>));

        if let Syntax::Escape(tokens) = &syntax[1].0 {
            let tokens = tokens.clone().into_iter().collect::<Vec<TokenTree>>();

            assert_eq!(tokens.len(), 1);
            if let TokenTree::Ident(_) = tokens[0] {
                assert_eq!(tokens[0].to_string(), "abc");
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "invalid number literal (invalid digit found in string)")]
    fn parse_invalid_int() {
        parse(quote!(OP_CHECKSIG 12g34));
    }

    #[test]
    fn parse_int() {
        let syntax = parse(quote!(OP_CHECKSIG 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, 1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "expected negative sign to be followed by number literal")]
    fn parse_invalid_negative_sign() {
        parse(quote!(OP_CHECKSIG - OP_HASH160));
    }

    #[test]
    fn parse_negative_int() {
        let syntax = parse(quote!(OP_CHECKSIG - 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, -1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    fn parse_hex() {
        let syntax = parse(quote!(OP_CHECKSIG 0x123456789abcde));

        if let Syntax::Bytes(bytes) = &syntax[1].0 {
            assert_eq!(bytes, &vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        } else {
            panic!("Unable to cast Syntax as Syntax::Bytes")
        }
    }
}
