// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use chrono::{DateTime, Duration, Utc};
use http::{header::USER_AGENT, StatusCode};
use reqwest::Client;
use serde::Deserialize;
use std::{fmt::Debug, sync::{Arc, RwLock}};

use crate::{GitHubAppAuthenticator, TokenRequest, GitHubAuthenticatorError, GitHubInstallationToken};

#[derive(Deserialize)]
pub(crate) struct GitHubInstallationTokenResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// An authenticator for fetching access tokens for a given GitHub App installation
#[derive(Debug)]
pub struct GitHubInstallationAuthenticator {
    app: GitHubAppAuthenticator,
    inner: Client,
    installation_api_endpoint: String,
}

impl GitHubInstallationAuthenticator {
    pub(crate) fn new(app: GitHubAppAuthenticator, installation_id: u32) -> Self {
        let endpoint = format!("{}/app/installations/{}/access_tokens", app.base_endpoint(), installation_id);
        GitHubInstallationAuthenticator {
            app,
            inner: Client::new(),
            installation_api_endpoint: endpoint
        }
    }

    /// Upgrade this authenticator into an authenticator that keeps a token alive.
    pub fn into_refreshing(self, request: TokenRequest) -> RefreshingGitHubInstallationAuthenticator {
        RefreshingGitHubInstallationAuthenticator::new(self, request)
    }

    /// Fetch a new access token for a given request on this installation
    pub async fn access_token(&self, request: &TokenRequest) -> Result<String, GitHubAuthenticatorError> {
        Ok(self.request_token(request).await?.token)
    }

    async fn request_token(
        &self,
        request: &TokenRequest,
    ) -> Result<GitHubInstallationTokenResponse, GitHubAuthenticatorError> {
        tracing::info!("Requesting installation access token");

        let jwt = self.app.generate_jwt(Duration::seconds(60))?;
        let response = self
            .inner
            .post(&self.installation_api_endpoint)
            .bearer_auth(jwt)
            .header(USER_AGENT, self.app.user_agent())
            .json(request)
            .send()
            .await?;

        if response.status() == StatusCode::CREATED {
            let body = response.text().await?;
            let token: GitHubInstallationTokenResponse =
                serde_json::from_str(&body).map_err(|err| {
                    tracing::error!(
                        ?err,
                        "Failed to decode installation access token response body"
                    );
                    GitHubAuthenticatorError::FailedToDecodeAccessTokenResponse
                })?;

            Ok(token)
        } else {
            tracing::error!(status = ?response.status(), "Failed to request installation access token");
            Err(GitHubAuthenticatorError::InstallationRequestFailed(
                response.status(),
            ))
        }
    }
}

/// An authenticator for continually fetching an access token for a given GitHub App installation
/// and permissions request pair. 
#[derive(Debug)]
pub struct RefreshingGitHubInstallationAuthenticator {
    authenticator: GitHubInstallationAuthenticator,
    request: TokenRequest,
    token: Arc<RwLock<Option<GitHubInstallationToken>>>,
}

impl RefreshingGitHubInstallationAuthenticator {
    fn new(authenticator: GitHubInstallationAuthenticator, request: TokenRequest) -> Self {
        Self {
            authenticator,
            request,
            token: Arc::new(RwLock::new(None)),
        }
    }

    fn token_expired(&self) -> bool {
        let token = self.token.read().unwrap();
        token.is_none() || token.as_ref().unwrap().expires_at <= Utc::now()
    }

    /// Fetch an updated access token for the configured request.
    pub async fn access_token(&self) -> Result<String, GitHubAuthenticatorError> {
        if self.token_expired() {
            let token = GitHubInstallationToken::from(self.authenticator.request_token(&self.request).await?);
            *self.token.write().unwrap() = Some(token);
        }

        Ok(self.token.read().unwrap().as_ref().unwrap().access_token.clone())
    }
}
