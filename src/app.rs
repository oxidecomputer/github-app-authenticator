// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use chrono::{Duration, Utc};
use http::HeaderValue;
use jsonwebtoken::{Header, Algorithm, EncodingKey};
use reqwest::Client;
use serde::Serialize;
use std::{fmt::Debug, ops::Add};
use tracing::debug;

use crate::{GitHubInstallationAuthenticator, GitHubAuthenticatorError};

static GITHUB_API_BASE: &str = "https://api.github.com";

/// An authenticator for generating installation authenticators.
#[derive(Clone)]
pub struct GitHubAppAuthenticator {
    inner: Client,
    app_id: u32,
    key: Vec<u8>,
    base_endpoint: String,
    user_agent: HeaderValue,
}

impl Debug for GitHubAppAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubInstallationAuthenticator")
            .field("app_id", &self.app_id)
            .finish()
    }
}

impl GitHubAppAuthenticator {

    /// Creates a new app authenticator. An app authenticator is used to create individual
    /// installation authenticators.
    pub fn new(
        app_id: u32,
        key: Vec<u8>,
        user_agent: HeaderValue,
    ) -> Self {
        debug!(?app_id, ?user_agent, "Creating app authenticator");

        Self {
            inner: Client::new(),
            app_id,
            key,
            base_endpoint: GITHUB_API_BASE.to_string(),
            user_agent,
        }
    }

    /// Configure the client to send requests via.
    pub fn with_client(&mut self, client: Client) -> &mut Self {
        self.inner = client;
        self
    }

    /// Configure base uri of the API to send requests to.
    pub fn with_base_uri<T>(&mut self, base_endpoint: T) -> &mut Self where T: ToString {
        self.base_endpoint = base_endpoint.to_string();
        self
    }

    /// Generate a new JWT for calling GitHub App endpoints.
    pub fn generate_jwt(&self, duration: Duration) -> Result<String, GitHubAuthenticatorError> {
        let claims = GitHubAppClaims {
            iat: Utc::now().timestamp(),
            exp: Utc::now().add(duration).timestamp(),
            iss: self.app_id,
        };

        jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(&self.key).map_err(|err| {
                tracing::error!(?err, "Failed to create JWT key");
                GitHubAuthenticatorError::FailedToParseKey
            })?,
        )
        .map_err(|err| {
            tracing::error!(?claims, ?err, "Failed to generate authentication JWT");
            GitHubAuthenticatorError::FailedToGenerateJwt(err)
        })
    }

    /// Generate an installation authenticator. Each installation authenticator receives its own
    /// copy of the app authenticator. Internal JWT credentials are not shared are not shared across
    /// installation authenticators.
    pub fn installation_authenticator(&self, installation_id: u32) -> GitHubInstallationAuthenticator {
        GitHubInstallationAuthenticator::new(self.clone(), installation_id)
    }

    // Get the user agent header.
    pub fn user_agent(&self) -> HeaderValue {
        self.user_agent.clone()
    }

    // Get the base API endpoint.
    pub(crate) fn base_endpoint(&self) -> &str {
        &self.base_endpoint
    }
}

#[derive(Debug, Serialize)]
struct GitHubAppClaims {
    iat: i64,
    exp: i64,
    iss: u32,
}
