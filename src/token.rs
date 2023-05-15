// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use chrono::{DateTime, Utc, Duration};
use serde::Serialize;
use std::{fmt::Debug, ops::Sub};

use crate::{permissions::Permissions, GitHubInstallationTokenResponse};

/// A request for generating an access token with a specific set of permissions for a specific set
/// of repositories. The GitHub App must already be granted all of the requested permissions on the
/// requested repositories.
#[derive(Debug, Default, Serialize)]
pub struct TokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Permissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<u32>>,
}

pub(crate) struct GitHubInstallationToken {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
}

impl Debug for GitHubInstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubInstallationToken")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl From<GitHubInstallationTokenResponse> for GitHubInstallationToken {
    fn from(value: GitHubInstallationTokenResponse) -> Self {
        Self {
            access_token: value.token,
            // Subtract 5 minutes from the expiration time that GitHub specifies to alleviate
            // potential clock skew and race conditions
            expires_at: value.expires_at.sub(Duration::minutes(5)),
        }
    }
}