//! `#[derive(Manifest)]` — describe a Rust struct as a Keel manifest.
//!
//! Built against `docs/keel/DERIVE.md` (evidence, not imagination: ndn-lab's flat
//! `FabricGauges` and nested `SceneSnapshot`). The derive **stops at "describe the
//! struct"** — it never names an intent, renderer, or app (Law #1). It emits, on
//! the struct:
//!
//! - `marker_term()` / `record_term()` — the type as a top-level marker (fields
//!   are separate field terms) and as a nested `record{…}` term.
//! - `schema()` / `record_schema()` — their hashes (the pin-test handle, and the
//!   `term-of(…)` reference nested fields resolve to).
//! - `field_terms()` / `manifest_terms()` — the vocabulary contribution.
//! - `to_manifest(describes)` / `to_record_value()` — `Result<_, DescribeError>`,
//!   fallible because `f64 → Decimal` can refuse a non-finite value (F55-B).
//!
//! Rulings encoded: declaration order is identity (R11 — never reordered);
//! cardinality declares, list-ness encodes (F55-A); floats are a declared loss
//! with a mandatory `#[field(decimal(places = N))]` (F55-B). The judgment-bearing
//! runtime lives in `ndn-manifest-describe`; this crate only wires field access to
//! it. Tool tier: generated code calls the spec crates, never the reverse (C7).

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type};

#[proc_macro_derive(Manifest, attributes(manifest, field))]
pub fn derive_manifest(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(|e| e.to_compile_error()).into()
}

/// A field's Keel shape, classified from its Rust type + `#[field(...)]` attrs.
enum Shape {
    Int,
    Text,
    Name,
    Bool,
    Bytes,
    HashKind,
    Decimal { places: u32 },
    Nested(syn::Path),
    /// `Option<T>`; `absent` = the `nonfinite = absent` opt-in (decimal inner only).
    Opt(Box<Shape>, bool),
    /// `Vec<T>`; `some` = `#[field(some)]` (cardinality Some, ≥1).
    Many(Box<Shape>, bool),
}

struct FieldPlan {
    label: String,
    doc: String,
    shape: Shape,
    ident: syn::Ident,
}

fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(&input, "Manifest can only derive on structs"));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(&input, "Manifest needs named fields"));
    };

    // Container: `#[manifest(ty = "…", describes = "…")]` + the struct's own doc.
    let mut ty_label = pascal_to_kebab(&name.to_string());
    let mut describes_tpl: Option<String> = None;
    for attr in &input.attrs {
        if attr.path().is_ident("manifest") {
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("ty") {
                    ty_label = m.value()?.parse::<syn::LitStr>()?.value();
                } else if m.path.is_ident("describes") {
                    describes_tpl = Some(m.value()?.parse::<syn::LitStr>()?.value());
                }
                Ok(())
            })?;
        }
    }
    let struct_doc = doc_of(&input.attrs);

    let mut plans = Vec::new();
    for f in &named.named {
        let ident = f.ident.clone().unwrap();
        let label = snake_to_kebab(&ident.to_string());
        let shape = classify(&f.ty, f)?;
        plans.push(FieldPlan { label, doc: doc_of(&f.attrs), shape, ident });
    }

    // Per-field fragments, built once with real accessors.
    let mut entries = Vec::new();
    let mut record_vals = Vec::new();
    let mut nested_terms_calls: Vec<TokenStream2> = Vec::new();
    for p in &plans {
        let id = &p.ident;
        let v = value_expr(&p.shape, &p.label, quote!(self.#id));
        let ft = field_term(p);
        entries.push(quote! {
            ndn_manifest::model::ManifestEntry {
                field: ndn_manifest::term_hash(&#ft).unwrap(),
                value: #v,
            }
        });
        record_vals.push(v);
        collect_nested(&p.shape, &mut nested_terms_calls);
    }

    let describes_default = match &describes_tpl {
        Some(s) => quote!(ndn_manifest::model::Subject::Name(#s.into())),
        None => quote!(ndn_manifest::model::Subject::Name(String::new())),
    };

    let record_fields2 = plans.iter().map(record_field);
    let field_terms2 = plans.iter().map(field_term);

    Ok(quote! {
        impl #name {
            /// The type as a top-level marker term (fields are separate field terms).
            pub fn marker_term() -> ndn_manifest::model::Term {
                ndn_manifest::model::Term {
                    label: #ty_label.into(),
                    doc: Some(#struct_doc.into()),
                    ty: None,
                    attrs: Vec::new(),
                }
            }
            /// The type as a nested `record{…}` term.
            pub fn record_term() -> ndn_manifest::model::Term {
                ndn_manifest::model::Term {
                    label: #ty_label.into(),
                    doc: Some(#struct_doc.into()),
                    ty: Some(ndn_manifest::model::TypeExpr::Record(vec![ #( #record_fields2 ),* ])),
                    attrs: Vec::new(),
                }
            }
            /// Hash of the marker term (the pin-test handle; the manifest's `ty`).
            pub fn schema() -> ndn_manifest::hash::Hash {
                ndn_manifest::term_hash(&Self::marker_term()).expect("marker term hashes")
            }
            /// Hash of the record term (what nested `term-of(…)` references resolve to).
            pub fn record_schema() -> ndn_manifest::hash::Hash {
                ndn_manifest::term_hash(&Self::record_term()).expect("record term hashes")
            }
            /// This struct's field terms (top-level, typed).
            pub fn field_terms() -> Vec<ndn_manifest::model::Term> {
                vec![ #( #field_terms2 ),* ]
            }
            /// Vocabulary contribution when this struct is a nested record.
            pub fn nested_terms() -> Vec<ndn_manifest::model::Term> {
                let mut v: Vec<ndn_manifest::model::Term> = Vec::new();
                #( #nested_terms_calls )*
                v.push(Self::record_term());
                v
            }
            /// Vocabulary contribution when this struct is a top-level manifest.
            pub fn manifest_terms() -> Vec<ndn_manifest::model::Term> {
                let mut v: Vec<ndn_manifest::model::Term> = Vec::new();
                #( #nested_terms_calls )*
                v.push(Self::marker_term());
                v.extend(Self::field_terms());
                v
            }
            /// The record value (positional) — this struct as a nested field.
            pub fn to_record_value(&self)
                -> Result<ndn_manifest::model::Value, ndn_manifest_describe::DescribeError> {
                Ok(ndn_manifest::model::Value::Record(vec![ #( #record_vals ),* ]))
            }
            /// The top-level manifest describing `describes`.
            pub fn to_manifest(&self, describes: ndn_manifest::model::Subject)
                -> Result<ndn_manifest::model::Manifest, ndn_manifest_describe::DescribeError> {
                Ok(ndn_manifest::model::Manifest {
                    ty: Self::schema(),
                    label: Some(#ty_label.into()),
                    describes,
                    entries: vec![ #( #entries ),* ],
                    edges: Vec::new(),
                })
            }
            /// `to_manifest` with the `#[manifest(describes = …)]` template subject.
            pub fn to_manifest_default(&self)
                -> Result<ndn_manifest::model::Manifest, ndn_manifest_describe::DescribeError> {
                self.to_manifest(#describes_default)
            }
        }
    })
}

/// Emit `v.extend(T::nested_terms());` for each nested-referencing field.
fn collect_nested(shape: &Shape, out: &mut Vec<TokenStream2>) {
    match shape {
        Shape::Nested(path) => out.push(quote! { v.extend(#path::nested_terms()); }),
        Shape::Opt(inner, _) | Shape::Many(inner, _) => collect_nested(inner, out),
        _ => {}
    }
}

/// A top-level field `Term` (typed; multiplicity via `list-of`).
fn field_term(p: &FieldPlan) -> TokenStream2 {
    let label = &p.label;
    let doc = &p.doc;
    let ty = type_expr_toplevel(&p.shape);
    quote! {
        ndn_manifest::model::Term {
            label: #label.into(),
            doc: Some(#doc.into()),
            ty: Some(#ty),
            attrs: Vec::new(),
        }
    }
}

/// A nested record `Field` (bare type + cardinality — F55-A).
fn record_field(p: &FieldPlan) -> TokenStream2 {
    let label = &p.label;
    let doc = &p.doc;
    let (ty, card) = type_expr_bare(&p.shape);
    quote! {
        ndn_manifest::model::Field {
            label: #label.into(),
            doc: Some(#doc.into()),
            ty: #ty,
            cardinality: #card,
            attrs: Vec::new(),
        }
    }
}

fn prim(kind: &str) -> TokenStream2 {
    let k = syn::Ident::new(kind, proc_macro2::Span::call_site());
    quote!(ndn_manifest::model::TypeExpr::Primitive(ndn_manifest::model::PrimitiveKind::#k))
}

/// Top-level type: `list-of` carries multiplicity (a Term has no cardinality slot).
fn type_expr_toplevel(shape: &Shape) -> TokenStream2 {
    match shape {
        Shape::Int => prim("Integer"),
        Shape::Text => prim("Text"),
        Shape::Name => prim("Name"),
        Shape::Bool => prim("Boolean"),
        Shape::Bytes => prim("Bytes"),
        Shape::HashKind => prim("Hash"),
        Shape::Decimal { .. } => prim("Decimal"),
        Shape::Nested(path) => quote!(ndn_manifest::model::TypeExpr::TermOf(#path::record_schema())),
        Shape::Opt(inner, _) | Shape::Many(inner, _) => {
            let it = type_expr_toplevel(inner);
            quote!(ndn_manifest::model::TypeExpr::ListOf(Box::new(#it)))
        }
    }
}

/// Nested type: the bare type + a `Cardinality` the wrapper implies (F55-A).
fn type_expr_bare(shape: &Shape) -> (TokenStream2, TokenStream2) {
    let one = quote!(ndn_manifest::model::Cardinality::One);
    match shape {
        Shape::Opt(inner, _) => {
            let (ty, _) = type_expr_bare(inner);
            (ty, quote!(ndn_manifest::model::Cardinality::Optional))
        }
        Shape::Many(inner, some) => {
            let (ty, _) = type_expr_bare(inner);
            let c = if *some {
                quote!(ndn_manifest::model::Cardinality::Some)
            } else {
                quote!(ndn_manifest::model::Cardinality::Many)
            };
            (ty, c)
        }
        Shape::Nested(path) => {
            (quote!(ndn_manifest::model::TypeExpr::TermOf(#path::record_schema())), one)
        }
        other => (type_expr_toplevel(other), one),
    }
}

/// The `Value` expression for a field, accessed via `acc` (e.g. `self.x`).
fn value_expr(shape: &Shape, label: &str, acc: TokenStream2) -> TokenStream2 {
    match shape {
        Shape::Int => quote!(ndn_manifest::model::Value::Integer((#acc) as u64)),
        Shape::Text => quote!(ndn_manifest::model::Value::Text((#acc).clone())),
        Shape::Name => quote!(ndn_manifest::model::Value::Name((#acc).clone())),
        Shape::Bool => quote!(ndn_manifest::model::Value::Boolean(#acc)),
        Shape::Bytes => quote!(ndn_manifest::model::Value::Bytes((#acc).clone())),
        Shape::HashKind => quote!(ndn_manifest::model::Value::Hash(#acc)),
        Shape::Decimal { places } => {
            quote!(ndn_manifest_describe::decimal(#acc, #places, #label)?)
        }
        Shape::Nested(_) => quote!((#acc).to_record_value()?),
        Shape::Opt(inner, absent) => {
            if let (Shape::Decimal { places }, true) = (inner.as_ref(), absent) {
                quote!(ndn_manifest_describe::optional((#acc).and_then(|__v| ndn_manifest_describe::decimal_or_none(__v, #places))))
            } else {
                let inner_expr = value_expr_ref(inner, label);
                quote!(ndn_manifest_describe::optional(match &#acc {
                    Some(__v) => Some(#inner_expr),
                    None => None,
                }))
            }
        }
        Shape::Many(inner, _) => {
            let inner_expr = value_expr_ref(inner, label);
            quote!(ndn_manifest_describe::list({
                let mut __out: Vec<ndn_manifest::model::Value> = Vec::new();
                for __v in &#acc { __out.push(#inner_expr); }
                __out
            }))
        }
    }
}

/// Value expression where the accessor is `__v: &Inner` (inside Option/Vec).
fn value_expr_ref(shape: &Shape, label: &str) -> TokenStream2 {
    match shape {
        Shape::Int => quote!(ndn_manifest::model::Value::Integer((*__v) as u64)),
        Shape::Text => quote!(ndn_manifest::model::Value::Text((*__v).clone())),
        Shape::Name => quote!(ndn_manifest::model::Value::Name((*__v).clone())),
        Shape::Bool => quote!(ndn_manifest::model::Value::Boolean(*__v)),
        Shape::Bytes => quote!(ndn_manifest::model::Value::Bytes((*__v).clone())),
        Shape::HashKind => quote!(ndn_manifest::model::Value::Hash(*__v)),
        Shape::Decimal { places } => quote!(ndn_manifest_describe::decimal(*__v, #places, #label)?),
        Shape::Nested(_) => quote!(__v.to_record_value()?),
        // Nested Option/Vec inside Option/Vec is not exercised by either real
        // producer; deliberately unsupported (DERIVE.md "open").
        Shape::Opt(_, _) | Shape::Many(_, _) => {
            quote!(compile_error!("nested Option/Vec of Option/Vec is unsupported (unexercised)"))
        }
    }
}

/// Classify a Rust type + its `#[field(...)]` attrs into a [`Shape`].
fn classify(ty: &Type, field: &syn::Field) -> syn::Result<Shape> {
    // Field attrs.
    let mut places: Option<u32> = None;
    let mut is_name = false;
    let mut is_some = false;
    let mut nonfinite_absent = false;
    for attr in &field.attrs {
        if attr.path().is_ident("field") {
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("decimal") {
                    m.parse_nested_meta(|d| {
                        if d.path.is_ident("places") {
                            places = Some(d.value()?.parse::<syn::LitInt>()?.base10_parse()?);
                        }
                        Ok(())
                    })?;
                } else if m.path.is_ident("name") {
                    is_name = true;
                } else if m.path.is_ident("some") {
                    is_some = true;
                } else if m.path.is_ident("nonfinite") {
                    nonfinite_absent = m.value()?.parse::<syn::Ident>()? == "absent";
                }
                Ok(())
            })?;
        }
    }
    classify_ty(ty, places, is_name, is_some, nonfinite_absent)
}

fn classify_ty(
    ty: &Type,
    places: Option<u32>,
    is_name: bool,
    is_some: bool,
    nonfinite_absent: bool,
) -> syn::Result<Shape> {
    let Type::Path(tp) = ty else {
        return Err(syn::Error::new_spanned(ty, "unsupported field type for Manifest"));
    };
    let seg = tp.path.segments.last().unwrap();
    let name = seg.ident.to_string();
    match name.as_str() {
        "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" => Ok(Shape::Int),
        "bool" => Ok(Shape::Bool),
        "String" | "str" => Ok(if is_name { Shape::Name } else { Shape::Text }),
        "f32" | "f64" => match places {
            Some(p) => Ok(Shape::Decimal { places: p }),
            None => Err(syn::Error::new_spanned(
                ty,
                "float fields need #[field(decimal(places = N))] — the loss must be declared (F55-B)",
            )),
        },
        "Hash" => Ok(Shape::HashKind),
        "Option" => {
            let inner = generic_arg(seg, ty)?;
            Ok(Shape::Opt(
                Box::new(classify_ty(inner, places, is_name, false, nonfinite_absent)?),
                nonfinite_absent,
            ))
        }
        "Vec" => {
            let inner = generic_arg(seg, ty)?;
            // Vec<u8> is Bytes (a primitive), before the many-T rule fires.
            if let Type::Path(itp) = inner
                && itp.path.segments.last().unwrap().ident == "u8" {
                    return Ok(Shape::Bytes);
                }
            Ok(Shape::Many(
                Box::new(classify_ty(inner, places, is_name, false, nonfinite_absent)?),
                is_some,
            ))
        }
        _ => Ok(Shape::Nested(tp.path.clone())),
    }
}

fn generic_arg<'a>(seg: &'a syn::PathSegment, ty: &Type) -> syn::Result<&'a Type> {
    if let syn::PathArguments::AngleBracketed(a) = &seg.arguments
        && let Some(syn::GenericArgument::Type(t)) = a.args.first() {
            return Ok(t);
        }
    Err(syn::Error::new_spanned(ty, "expected a single generic type argument"))
}

/// Collect `#[doc = "…"]` into a trimmed single line (matches hand-authored docs).
fn doc_of(attrs: &[syn::Attribute]) -> String {
    let mut parts = Vec::new();
    for a in attrs {
        if a.path().is_ident("doc")
            && let syn::Meta::NameValue(nv) = &a.meta
                && let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) = &nv.value {
                    parts.push(s.value().trim().to_string());
                }
    }
    parts.join(" ").trim().to_string()
}

fn snake_to_kebab(s: &str) -> String {
    s.replace('_', "-")
}

fn pascal_to_kebab(s: &str) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
