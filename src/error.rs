// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use http::StatusCode;
use reqwest::Error as ClientError;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitHubAuthenticatorError {
    #[error("Failed to send request {0}")]
    Client(#[from] ClientError),
    #[error("Failed to decode access token from GitHub")]
    FailedToDecodeAccessTokenResponse,
    #[error(transparent)]
    FailedToGenerateJwt(jsonwebtoken::errors::Error),
    #[error("Failed to parse private key")]
    FailedToParseKey,
    #[error(transparent)]
    FailedToParseEnvValue(#[from] ParseIntError),
    #[error("Installation token request failed {0}")]
    InstallationRequestFailed(StatusCode),
}