// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use serde::Serialize;

/// Capability permission level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadOnly {
    Read,
}

/// Capability permission level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteOnly {
    Write,
}

/// Capability permission level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadWrite {
    Read,
    Write,
}

/// Capability permission level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadWriteAdmin {
    Read,
    Write,
    Admin,
}

/// The permissions that can be assigned to an access token.
#[derive(Debug, Default, Serialize)]
pub struct Permissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub administration: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployments: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environments: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_requests: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_hooks: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_projects: Option<ReadWriteAdmin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_scanning_alerts: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_events: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_file: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statuses: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_alerts: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflows: Option<WriteOnly>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_administration: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_custom_roles: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_announcement_banners: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_hooks: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_personal_access_tokens: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_personal_access_token_requests: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_plan: Option<ReadOnly>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_projects: Option<ReadWriteAdmin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_packages: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_secrets: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_self_hosted_runners: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_user_blocking: Option<ReadWrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_discussions: Option<ReadWrite>,
}
