use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};

#[component]
pub fn Faces() -> Element {
    let ctx = use_context::<AppCtx>();
    let faces = ctx.faces.read();

    let mut new_uri: Signal<String> = use_signal(String::new);

    rsx! {
        // ── Face table ──────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Active Faces" }
            if faces.is_empty() {
                div { class: "empty", "No faces registered." }
            } else {
                table {
                    thead {
                        tr {
                            th { "ID" }
                            th { "Kind" }
                            th { "Remote URI" }
                            th { "Local URI" }
                            th { "Persistency" }
                            th { "" }
                        }
                    }
                    tbody {
                        for face in faces.iter() {
                            {
                                let face_id = face.face_id;
                                rsx! {
                                    tr {
                                        td { class: "mono", "{face.face_id}" }
                                        td {
                                            span {
                                                class: "{face.kind_badge_class()}",
                                                "{face.kind_label()}"
                                            }
                                        }
                                        td { class: "mono",
                                            "{face.remote_uri.as_deref().unwrap_or(\"—\")}"
                                        }
                                        td { class: "mono",
                                            "{face.local_uri.as_deref().unwrap_or(\"—\")}"
                                        }
                                        td { "{face.persistency}" }
                                        td {
                                            button {
                                                class: "btn btn-danger btn-sm",
                                                onclick: move |_| ctx.cmd.send(DashCmd::FaceDestroy(face_id)),
                                                "Destroy"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Create face form ─────────────────────────────────────────────
            div { class: "form-row",
                div { class: "form-group", style: "flex:1;",
                    label { r#for: "face-uri", "Face URI" }
                    input {
                        id: "face-uri",
                        r#type: "text",
                        placeholder: "udp4://192.168.1.1:6363",
                        value: "{new_uri}",
                        oninput: move |e| new_uri.set(e.value()),
                        onkeydown: move |e| {
                            if e.key() == Key::Enter {
                                let uri = new_uri.read().trim().to_string();
                                if !uri.is_empty() {
                                    ctx.cmd.send(DashCmd::FaceCreate(uri));
                                    new_uri.set(String::new());
                                }
                            }
                        },
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let uri = new_uri.read().trim().to_string();
                        if !uri.is_empty() {
                            ctx.cmd.send(DashCmd::FaceCreate(uri));
                            new_uri.set(String::new());
                        }
                    },
                    "Create Face"
                }
            }
            div { style: "margin-top:8px;font-size:12px;color:var(--text-muted);",
                "Supported: udp4://<ip>:6363  tcp4://<ip>:6363  ws://<ip>:9696  unix:///path  shm://name  ether://<iface>"
            }
        }
    }
}
