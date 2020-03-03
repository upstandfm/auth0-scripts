// NOTE: the code below has been pasted into the Auth0 hooks editor:
// https://manage.auth0.com/dashboard/eu/upstandfm/hooks

'use strict';

// Note that the depencencies and secrets can be configured via the hooks editor
// by clicking on the settings icon
const fetch = require('node-fetch');
const auth0 = require('auth0');

/**
 * Get an access token to interact with the Upstand FM API.
 *
 * The only Auth0 app authorized to create workspace members and update an
 * invite status is:
 * https://manage.auth0.com/dashboard/eu/upstandfm/applications/nmq1x6mfDXzDJxwRYaLKKNN4SCKPpLnr/settings
 *
 * This client has the following "special" scope:
 * - "create:workspace-member"
 * - "update:workspace-invite-status"
 *
 * @param {Object} secrets - Webtask secrets (config)
 *
 * @param {String} secrets.CREATE_WORKSPACE_MEMBER_CLIENT_ID
 * @param {String} secrets.CREATE_WORKSPACE_MEMBER_CLIENT_SECRET
 * @param {String} secrets.AUDIENCE
 * @param {String} secrets.TOKEN_ENDPOINT
 *
 * @return {Promise} Resolves with access token string
 */
async function _getToken(secrets) {
  const options = {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      client_id: secrets.CREATE_WORKSPACE_MEMBER_CLIENT_ID,
      client_secret: secrets.CREATE_WORKSPACE_MEMBER_CLIENT_SECRET,
      audience: secrets.AUDIENCE,
      grant_type: 'client_credentials'
    })
  };
  const res = await fetch(secrets.TOKEN_ENDPOINT, options);

  if (!res.ok) {
    throw new Error('Failed to fetch token');
  }

  const { access_token } = await res.json();
  return access_token;
}

/**
 * Create a workspace member.
 *
 * @param {String} token
 * @param {String} workspaceId
 * @param {String} userId
 * @param {String} email
 *
 * @return {Promise} Resolves with the created member
 */
async function _createMember(token, workspaceId, userId, email) {
  const url = `https://api.upstand.fm/workspaces/${workspaceId}/members`;
  const options = {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({
      userId,
      email,
      fullName: 'User'
    })
  };
  const res = await fetch(url, options);

  if (!res.ok) {
    throw new Error('Failed to create workspace member');
  }

  return res.json();
}

/**
 * Auth0 hook to create a workspace member on password reset.
 *
 * For more info see:
 * https://auth0.com/docs/hooks/extensibility-points/post-change-password
 *
 * @param {Object} user
 * @param {String} user.id
 * @param {String} user.username
 * @param {String} user.email
 * @param {String} user.last_password_reset - exact date/time the user's password was changed
 *
 * @param {Object} context - Auth0 connection and other context info
 * @param {Object} context.connection
 * @param {Object} context.connection.id
 * @param {Object} context.connection.name
 * @param {Object} context.connection.tenant
 * @param {Object} context.webtask - webtask context
 *
 * @param {Function} cb
 */
module.exports = async function createWorkspaceMember(user, context, cb) {
  try {
    const { secrets } = context.webtask;

    // To interact with the Auth0 management API, we use a "Non Interactive
    // Client" to fetch an access_token via the Client Credentials Grant
    //
    // Using the "clientId" and "clientSecret", the client fetches and caches
    // the token for the duration of the returned "expires_in" value
    //
    // We use a "special" app to interact with the Auth0 Management API:
    // https://manage.auth0.com/dashboard/eu/upstandfm/applications/8qtgbkmps3w1uAphTR8o7YDX03Zj2FIG/settings
    //
    // For more info see:
    // https://auth0.github.io/node-auth0/module-management.ManagementClient.html
    const managementClient = new auth0.ManagementClient({
      domain: secrets.AUTH0_DOMAIN,
      clientId: secrets.ACCOUNT_CLIENT_ID,
      clientSecret: secrets.ACCOUNT_CLIENT_SECRET
    });

    const userId = `auth0|${user.id}`;

    // For SDK docs see:
    // https://auth0.github.io/node-auth0/module-management.ManagementClient.html#getUser
    const { app_metadata = {} } = await managementClient.getUser({
      id: userId
    });

    // We only run this hook when a password reset results from an "invite"
    // Auth0 doesn't have an "user invite API", so me must abuse the password
    // reset flow in order to mimic an invite flow.
    if (!app_metadata.isUserInvite) {
      return;
    }

    const token = await _getToken(secrets);
    await _createMember(token, app_metadata.workspaceId, userId, user.email);

    // TODO: update invite status

    // We have to explicitly set new values, e.g. we can't delete properties,
    // because Auth0 does some weird stuff with merging metadata object props
    //
    // For more info see:
    // https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id
    const newAppMetadata = {
      isUserInvite: false,
      inviteMsg: ''
    };

    // For SDK docs see:
    // https://auth0.github.io/node-auth0/module-management.ManagementClient.html#updateAppMetadata
    await managementClient.updateAppMetadata({ id: userId }, newAppMetadata);

    cb();
  } catch (err) {
    cb(err);
  }
};
