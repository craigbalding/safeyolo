//! Controlled native TCP/UDS callers prove shared operations. Guest-origin and
//! isolation observations belong to installed_shared_approvals.py on systrap.

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use std::{fs, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};

use crate::test_owned_endpoint;

pub(crate) const LIMIT: Duration = Duration::from_secs(5);
pub(crate) const WORKER_ID: &str = "ag-11111111111111111111111111111111";
pub(crate) const HELPER_ID: &str = "ag-22222222222222222222222222222222";
pub(crate) const SECRET: &str = "synthetic-secret-821-do-not-disclose";

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) head: String,
    pub(crate) body: Vec<u8>,
}
impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON response")
    }
    pub(crate) fn id(&self) -> String {
        self.head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-safeyolo-request-id"))
            .expect("trusted request ID")
            .1
            .trim()
            .into()
    }
}

async fn receive(stream: &mut (impl AsyncReadExt + Unpin)) -> Reply {
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let end = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("HTTP head")
        + 4;
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        head,
        body: bytes[end..].into(),
    }
}

pub(crate) struct Fixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) proxy: Proxy,
    pub(crate) admin: u16,
    pub(crate) address: std::net::SocketAddr,
    pub(crate) origin: Arc<tokio::net::TcpListener>,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        Self::with_retention(1000).await
    }

    pub(crate) async fn with_retention(max_flows: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::create_dir(root.path().join("builtin-services")).unwrap();
        fs::create_dir(root.path().join("services")).unwrap();
        fs::write(data.join("agent_token"), "synthetic-agent-token").unwrap();
        fs::write(root.path().join("admin_token"), "synthetic-operator-token").unwrap();
        let (origin, address) = test_owned_endpoint::bind().await;
        fs::write(root.path().join("policy.toml"), format!(
            "budget=40\n[hosts]\n'{address}'={{egress='prompt'}}\n[agents.worker]\nagent_id='{WORKER_ID}'\n[agents.helper]\nagent_id='{HELPER_ID}'\n[agents.peer]\nagent_id='ag-33333333333333333333333333333333'\n[controls.credentials]\nenabled=false\n"
        )).unwrap();
        let config: Config = serde_json::from_value(json!({
            "native_product":true,"data_dir":data,"flow_pruner_max":max_flows,"policy_file":root.path().join("policy.toml"),
            "listeners":(["worker","helper","peer"].map(|name| json!({"agent_id":name,"socket_path":root.path().join(format!("{name}.sock"))}))),
            "admin_port":0,"admin_api_token_file":root.path().join("admin_token"),
            "readiness_file":root.path().join("ready.json"),"audit_log_path":root.path().join("audit.jsonl"),
            "event_log":root.path().join("events.jsonl"),"circuit_breaker_enabled":false,
            "flow_store_enabled":true,"flow_store_db_path":root.path().join("flows.sqlite3")
            ,"gateway_builtin_services_dir":root.path().join("builtin-services"),"gateway_services_dir":root.path().join("services")
        })).unwrap();
        let proxy = Proxy::start(config).await.unwrap();
        let ready: Value =
            serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
        let admin = ready["admin_port"]
            .as_u64()
            .expect("bound admin")
            .try_into()
            .unwrap();
        Self {
            root,
            proxy,
            admin,
            address,
            origin: Arc::new(origin),
        }
    }

    pub(crate) fn source(&self) -> String {
        fs::read_to_string(self.root.path().join("policy.toml")).unwrap()
    }

    pub(crate) async fn agent(
        &self,
        agent: &str,
        method: &str,
        path: &str,
        value: Option<Value>,
    ) -> Reply {
        let body = value.map(|value| value.to_string()).unwrap_or_default();
        let mut stream = UnixStream::connect(self.root.path().join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(format!("{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer synthetic-agent-token\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    pub(crate) async fn admin(&self, method: &str, path: &str, value: Option<Value>) -> Reply {
        let body = value.map(|value| value.to_string()).unwrap_or_default();
        let mut stream = TcpStream::connect(("127.0.0.1", self.admin)).await.unwrap();
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    pub(crate) async fn network(&self, agent: &str, address: std::net::SocketAddr) -> Reply {
        let mut stream = UnixStream::connect(self.root.path().join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(format!("GET http://{address}/marker HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    pub(crate) async fn apply(&self, source: &str) {
        let result = self
            .admin(
                "PUT",
                "/admin/policy/baseline",
                Some(json!({"source":source})),
            )
            .await;
        assert_eq!(result.status, 200, "{}", result.json());
    }

    pub(crate) async fn selected(&self) -> String {
        let blocked = self.network("worker", self.address).await;
        assert_eq!(blocked.status, 428);
        assert!(
            timeout(Duration::from_millis(30), self.origin.accept())
                .await
                .is_err(),
            "blocked request reached origin"
        );
        let id = blocked.id();
        assert_eq!(
            self.agent("helper", "GET", &format!("/approvals/{id}"), None)
                .await
                .status,
            404
        );
        let mut source = self.source();
        source = source.replace(&format!("agent_id='{HELPER_ID}'"), &format!(
            "agent_id='{HELPER_ID}'\nevidence_reads=[{{reader_id='{HELPER_ID}',agent='worker',agent_id='{WORKER_ID}',request_id='{id}',reads=['diagnostic','approval']}}]"));
        self.apply(&source).await;
        let preview = self
            .agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await;
        assert_eq!(preview.status, 200, "{}", preview.json());
        assert!(
            preview.json()["effect"]
                .as_str()
                .unwrap()
                .contains("reusable network access")
        );
        assert_eq!(preview.json()["action"]["agent_id"], WORKER_ID);
        id
    }

    pub(crate) async fn prepare(&self, id: &str, reason: &str) -> Reply {
        let action = self
            .agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .json()["action"]
            .clone();
        self.agent(
            "helper",
            "POST",
            &format!("/approvals/{id}/prepare"),
            Some(json!({"action":action,"reason":reason})),
        )
        .await
    }

    pub(crate) async fn resolve(&self, id: &str, decision: &str) -> Reply {
        self.admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":decision})),
        )
        .await
    }

    pub(crate) async fn stop(self) {
        self.proxy.shutdown().await;
    }
}
