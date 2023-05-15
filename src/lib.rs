// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Tools for authenticating API requests on behalf of GitHub Apps and GitHub App installations.
//!
//! ```no_run
//! # use github_app_authenticator::{GitHubAuthenticatorError, TokenRequest, permissions::{Permissions, ReadWrite}, GitHubAppAuthenticator, headers::HeaderValue};
//! # async fn example() -> Result<(), GitHubAuthenticatorError> {
//! // Create an application authenticator
//! let app_id = 12345;
//! let key = vec![];
//! let app = GitHubAppAuthenticator::new(
//!   app_id,
//!   key,
//!   HeaderValue::from_static("test-authenticator")
//! );
//! 
//! // Create an individual authenticator for an installation
//! let installation_id = 67890;
//! let authenticator = app.installation_authenticator(installation_id);
//! 
//! // Create a request that allows for reading files
//! let mut request = TokenRequest::default();
//! let mut permissions = Permissions::default();
//! permissions.contents = Some(ReadWrite::Read);
//! request.permissions = Some(permissions);
//! 
//! // Request individual access tokens for the installation
//! let token_a = authenticator.access_token(&request).await?;
//! let token_b = authenticator.access_token(&request).await?;
//! 
//! assert!(token_a != token_b);
//! 
//! // Transform the installation authenticator into a refreshing authenticator that will
//! // continually generate tokens for the provided request
//! let refreshing = authenticator.into_refreshing(request);
//! 
//! // Requesting a token multiple times will return the same token until it expires
//! let token_c = refreshing.access_token().await?;
//! let token_d = refreshing.access_token().await?;
//! 
//! assert!(token_c == token_d);
//! # Ok(())
//! # }
//! ```

mod app;
mod error;
mod installation;
/// Permissions for constraining access tokens
pub mod permissions;
mod token;

pub use app::*;
pub use error::*;
pub mod headers {
    pub use http::HeaderValue;
}
pub use installation::*;
pub use token::*;

#[cfg(test)]
mod tests {
    use crate::GitHubAppAuthenticator;
    use crate::token::TokenRequest;
    use chrono::{DateTime, Utc, Duration};
    use http::HeaderValue;
    use pem_rfc7468::LineEnding;
    use rand::RngCore;
    use rsa::{pkcs1::EncodeRsaPrivateKey, RsaPrivateKey};
    use serde::{Deserialize, Serialize};
    use std::ops::Add;
    use std::mem;
    use wiremock::{
        matchers::{bearer_token, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn app_id() -> u32 {
        let mut rng = rand::thread_rng();
        rng.next_u32() as u32
    }

    fn installation_id() -> u32 {
        let mut rng = rand::thread_rng();
        rng.next_u32() as u32
    }

    fn private_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .unwrap()
            .to_pkcs1_pem(LineEnding::default())
            .unwrap()
            .to_string();

        private_key.into_bytes()
    }

    #[tokio::test]
    async fn test_requests_installation_token() {
        let server = MockServer::start().await;

        #[derive(Debug, Deserialize, Serialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: DateTime<Utc>,
        }

        let app_id = app_id();
        let key = private_key();
        let mut app = GitHubAppAuthenticator::new(
            app_id,
            key,
            HeaderValue::from_static("mock-authenticator")
        );
        app.with_base_uri(server.uri());
        let jwt = app.generate_jwt(Duration::seconds(60)).unwrap();

        let installation_id = installation_id();
        let authenticator = app.installation_authenticator(installation_id);

        let auth_response = ResponseTemplate::new(201)
            .set_delay(tokio::time::Duration::from_secs(1))
            .set_body_json(InstallationTokenResponse {
                token: "test-token".to_owned(),
                expires_at: Utc::now().add(chrono::Duration::seconds(3600)),
            });

        Mock::given(method("POST"))
            .and(path(format!(
                "/app/installations/{installation_id}/access_tokens"
            )))
            .and(bearer_token(jwt))
            .respond_with(auth_response)
            .expect(1)
            .mount(&server)
            .await;

        let token = authenticator
            .access_token(&TokenRequest::default())
            .await
            .unwrap();

        assert_eq!("test-token", &token);

        mem::drop(server);
    }

    #[tokio::test]
    async fn test_requests_installation_token_once() {
        let server = MockServer::start().await;

        #[derive(Debug, Deserialize, Serialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: DateTime<Utc>,
        }

        let app_id = app_id();
        let key = private_key();
        let mut app = GitHubAppAuthenticator::new(
            app_id,
            key,
            HeaderValue::from_static("mock-authenticator")
        );
        app.with_base_uri(server.uri());
        let jwt = app.generate_jwt(Duration::seconds(60)).unwrap();

        let installation_id = installation_id();
        let authenticator = app.installation_authenticator(installation_id);
        let refresher = authenticator.into_refreshing(TokenRequest::default());

        let auth_response = ResponseTemplate::new(201)
            .set_delay(tokio::time::Duration::from_secs(1))
            .set_body_json(InstallationTokenResponse {
                token: "test-token".to_owned(),
                expires_at: Utc::now().add(chrono::Duration::seconds(3600)),
            });

        Mock::given(method("POST"))
            .and(path(format!(
                "/app/installations/{installation_id}/access_tokens"
            )))
            .and(bearer_token(jwt))
            .respond_with(auth_response)
            .expect(1)
            .mount(&server)
            .await;

        let token = refresher.access_token().await.unwrap();

        assert_eq!("test-token", &token);

        let token = refresher.access_token().await.unwrap();

        assert_eq!("test-token", &token);

        mem::drop(server);
    }

    #[tokio::test]
    async fn test_requests_installation_token_twice() {
        let server = MockServer::start().await;

        #[derive(Debug, Deserialize, Serialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: DateTime<Utc>,
        }

        let app_id = app_id();
        let key = private_key();
        let mut app = GitHubAppAuthenticator::new(
            app_id,
            key,
            HeaderValue::from_static("mock-authenticator")
        );
        app.with_base_uri(server.uri());

        let installation_id = installation_id();
        let authenticator = app.installation_authenticator(installation_id);

        let refresher = authenticator.into_refreshing(TokenRequest::default());

        let auth_response = ResponseTemplate::new(201)
            .set_delay(tokio::time::Duration::from_secs(1))
            .set_body_json(InstallationTokenResponse {
                token: "test-token".to_owned(),
                expires_at: Utc::now(),
            });

        Mock::given(method("POST"))
            .and(path(format!(
                "/app/installations/{installation_id}/access_tokens"
            )))
            .respond_with(auth_response)
            .up_to_n_times(2)
            .expect(2)
            .mount(&server)
            .await;

        let token = refresher.access_token().await.unwrap();

        assert_eq!("test-token", &token);

        let token = refresher.access_token().await.unwrap();

        assert_eq!("test-token", &token);

        mem::drop(server);
    }
}
