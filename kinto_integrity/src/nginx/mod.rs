use crate::errors::*;
use crate::configuration;

const CONF: &str = "/etc/nginx/sites-available/default";

pub struct NginxBuilder {
    port: u16,
    redirect_port: u16,
    locations: Vec<String>
}

impl NginxBuilder {
    pub fn new() -> NginxBuilder {
        NginxBuilder { port: 0, redirect_port: 0, locations: vec![] }
    }
    pub fn location<T: ToString>(mut self, location: T) -> NginxBuilder {
        self.locations.push(location.to_string());
        self
    }
    pub fn port(mut self, port: u16) -> NginxBuilder {
        self.port = port;
        self
    }
    pub fn redirect(mut self, port: u16) -> NginxBuilder {
        self.redirect_port = port;
        self
    }
    pub fn build(self) -> IntegrityResult<Nginx> {
        if !configuration::prod() {
            return Ok(Nginx{})
        }
        std::fs::write(CONF, self.build_conf()).map_err(|err| {
            IntegrityError::new("failed to write a configuration file for Nginx").with_err(err).with_context(ctx!(
                ("file", CONF),
                ("contenst", self.build_conf())
            ))
        })?;
        Ok(Nginx{})
    }
    fn build_locations(&self) -> String {
        let mut locations: String = self.locations.join("|");
        locations.insert(0, '(');
        locations.push(')');
        locations
    }
    fn build_conf(&self) -> String {
        format!(r#"
upstream backend {{
    server localhost:{redirect_port};
}}

server {{
	listen {port} default_server;
	listen [::]:{port} default_server;
	server_name kintointegrity;

	location ~ ^/{locations} {{
		proxy_pass http://backend;
	}}

}}
"#, port=self.port, redirect_port=self.redirect_port, locations=self.build_locations())
    }
}

pub struct Nginx {}

impl Nginx {
    pub fn start(self) -> IntegrityResult<()> {
        if !configuration::prod() {
            return Ok(())
        }
        std::process::Command::new("nginx").spawn().map_err(|err| {
            IntegrityError::new("failed to start Nginx").with_err(err)
        })?.wait().map_err(|err| {
            IntegrityError::new("failed to start Nginx").with_err(err).
                with_context(ctx!(
                    ("config", String::from_utf8_lossy(&std::fs::read(CONF).unwrap_or(vec![])))
                ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templating() {
        let config = NginxBuilder::new().location("with_revocations").location("ccadb_cert_storage").port(80).redirect(8080).build_conf();
        println!("{}", config);
    }
}