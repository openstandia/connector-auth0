/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.auth0;

import com.auth0.client.HttpOptions;
import com.auth0.client.ProxyOptions;
import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.*;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.mgmt.*;
import com.auth0.json.mgmt.organizations.Members;
import com.auth0.json.mgmt.organizations.Organization;
import com.auth0.json.mgmt.organizations.OrganizationsPage;
import com.auth0.json.mgmt.organizations.Roles;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import com.auth0.net.AuthRequest;
import com.auth0.net.Request;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.auth0.Auth0Utils.resolvePageOffset;
import static jp.openstandia.connector.auth0.Auth0Utils.resolvePageSize;

public class Auth0Client {

    private static final Log LOG = Log.getLog(Auth0Client.class);

    private ManagementAPI internalClient;
    private Auth0Configuration configuration;

    protected TokenHolder tokenHolder;

    public void initClient(Auth0Configuration configuration) throws Auth0Exception {
        this.configuration = configuration;

        HttpOptions httpOptions = new HttpOptions();

        httpOptions.setConnectTimeout(configuration.getConnectionTimeoutInSeconds());
        httpOptions.setReadTimeout(configuration.getReadTimeoutInSeconds());
        httpOptions.setManagementAPIMaxRetries(configuration.getMaxRetries());

        // HTTP Proxy
        applyProxyIfNecessary(httpOptions);

        // Setup client
        refreshToken();
        internalClient = new ManagementAPI(this.configuration.getDomain(), tokenHolder.getAccessToken(), httpOptions);

        // Verify we can access the API
        checkClient();
    }

    private void applyProxyIfNecessary(HttpOptions httpOptions) {
        if (StringUtil.isNotEmpty(configuration.getHttpProxyHost())) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(configuration.getHttpProxyHost(), configuration.getHttpProxyPort()));
            ProxyOptions proxyOptions = new ProxyOptions(proxy);
            if (StringUtil.isNotEmpty(configuration.getHttpProxyUser())) {
                configuration.getHttpProxyPassword().access(c -> {
                    proxyOptions.setBasicAuthentication(configuration.getHttpProxyUser(), c.clone());
                });
            }
            httpOptions.setProxyOptions(proxyOptions);
        }
    }

    private void checkClient() throws Auth0Exception {
        if (internalClient == null) {
            throw new ConfigurationException("Not initialized Auth0 API client");
        }
        UserFilter filter = new UserFilter()
                .withPage(0, 1);
        Request<UsersPage> request = internalClient.users().list(filter);

        UsersPage response = request.execute();
    }

    protected void refreshToken() throws Auth0Exception {
        refreshToken(false);
    }

    protected void refreshToken(boolean force) throws Auth0Exception {
        if (configuration.getClientId() != null && configuration.getClientSecret() != null) {
            if (force || isExpired(tokenHolder, new Date())) {
                final AuthAPI[] authAPI = new AuthAPI[1];
                configuration.getClientSecret().access(c -> {
                    HttpOptions httpOptions = new HttpOptions();

                    // HTTP Proxy for auth
                    applyProxyIfNecessary(httpOptions);

                    authAPI[0] = new AuthAPI(configuration.getDomain(), configuration.getClientId(), String.valueOf(c), httpOptions);
                });
                AuthRequest authRequest = authAPI[0].requestToken(String.format("https://%s/api/v2/", configuration.getDomain()));
                tokenHolder = authRequest.execute();

                if (internalClient != null) {
                    internalClient.setApiToken(tokenHolder.getAccessToken());
                }
            }
        } else {
            throw new ConfigurationException("Not configured Client ID or Client Secret for the API client");
        }
    }

    protected boolean isExpired(TokenHolder holder, Date now) {
        if (holder == null) {
            return true;
        }
        long expiresAt = holder.getExpiresAt().getTime();
        long nowTime = now.getTime();

        if (nowTime + (60 * 1000) > expiresAt) {
            LOG.ok("Detected the token is expired");
            return true;
        }

        return false;
    }

    // Connection
    public List<Connection> getConnection(ConnectionFilter connectionFilter) throws Auth0Exception {
        List<Connection> conns = new ArrayList<>();

        withAuthPaging(connectionFilter, 0, 50, (filter, ignore) -> {
            Request<ConnectionsPage> request = internalClient.connections().listAll(filter);
            ConnectionsPage response = request.execute();

            conns.addAll(response.getItems());

            return response;
        });

        return conns;
    }

    // User

    public User createUser(User newUser) throws Auth0Exception {
        return withAuth(() -> {
            Request<User> request = internalClient.users().create(newUser);
            User response = request.execute();
            return response;
        });
    }

    public void updateUser(Uid uid, User patchUser) throws Auth0Exception {
        withAuth(() -> {
            // Reference: https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id
            // Some considerations:
            //
            // - The properties of the new object will replace the old ones.
            // - The metadata fields are an exception to this rule (user_metadata and app_metadata).
            //   These properties are merged instead of being replaced but be careful, the merge only occurs on the first level.
            // - If you are updating email, email_verified, phone_number, phone_verified, username or password of a secondary identity,
            //   you need to specify the connection property too.
            // - If you are updating email or phone_number you can specify, optionally, the client_id property.
            // - Updating email_verified is not supported for enterprise and passwordless sms connections.
            // - Updating the blocked to false does not affect the user's blocked state from an excessive amount of incorrectly
            //   provided credentials. Use the "Unblock a user" endpoint from the "User Blocks" API to change the user's state.
            Request<User> request = internalClient.users().update(uid.getUidValue(), patchUser);
            return request.execute();
        });
    }

    public void deleteUser(Uid uid) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.users().delete(uid.getUidValue());
            return request.execute();
        });
    }

    public User getUserByUid(String userId, UserFilter filter) throws Auth0Exception {
        return withAuth(() -> {
            Request<User> request = internalClient.users().get(userId, filter);
            User user = request.execute();
            return user;
        });
    }

    public List<User> getUsersByFilter(UserFilter filter) throws Auth0Exception {
        return withAuth(() -> {
            Request<UsersPage> request = internalClient.users().list(filter);
            UsersPage response = request.execute();
            return response.getItems();
        });
    }

    /**
     * Caution: This method returns users from all connections.
     * The results may have multiple users with same email.
     *
     * @param email
     * @param filter
     * @return
     * @throws Auth0Exception
     */
    public List<User> getUserByEmail(String email, FieldsFilter filter) throws Auth0Exception {
        return withAuth(() -> {
            Request<List<User>> request = internalClient.users().listByEmail(email, filter);
            List<User> response = request.execute();
            return response;
        });
    }

    public int getUsers(UserFilter userFilter, OperationOptions options, ResultHandlerFunction<User, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        return withAuthPaging(userFilter, pageInitialOffset, pageSize, (filter, skipCount) -> {
            Request<UsersPage> request = internalClient.users().list(filter);
            UsersPage response = request.execute();

            int count = 0;
            for (User u : response.getItems()) {
                if (count < skipCount) {
                    count++;
                    continue;
                }

                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    public void addRolesToUser(Uid uid, List<String> roleIds) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.users().addRoles(uid.getUidValue(), roleIds);
            return request.execute();
        });
    }

    public void removeRolesToUser(Uid uid, List<String> roleIds) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.users().removeRoles(uid.getUidValue(), roleIds);
            return request.execute();
        });
    }

    public List<Role> getRolesForUser(String userId) throws Auth0Exception {
        List<Role> roles = new ArrayList<>();

        withAuthPaging(new PageFilter(), 0, 50, (filter, ignore) -> {
            Request<RolesPage> request = internalClient.users().listRoles(userId, filter);
            RolesPage response = request.execute();

            roles.addAll(response.getItems());

            return response;
        });

        return roles;
    }

    public void addOrganizationsToUser(Uid uid, List<String> orgIds) throws Auth0Exception {
        Members members = new Members(Stream.of(uid.getUidValue()).collect(Collectors.toList()));
        // Unfortunately, we need to call this API per organization
        for (String orgId : orgIds) {
            withAuth(() -> {
                Request request = internalClient.organizations().addMembers(orgId, members);
                return request.execute();
            });
        }
    }

    public void removeOrganizationsToUser(Uid uid, List<String> orgIds) throws Auth0Exception {
        Members members = new Members(Stream.of(uid.getUidValue()).collect(Collectors.toList()));
        // Unfortunately, we need to call this API per organization
        for (String orgId : orgIds) {
            withAuth(() -> {
                Request request = internalClient.organizations().deleteMembers(orgId, members);
                return request.execute();
            });
        }
    }

    public List<Organization> getOrganizationsForUser(String userId) throws Auth0Exception {
        List<Organization> orgs = new ArrayList<>();

        withAuthPaging(new PageFilter(), 0, 50, (filter, ignore) -> {
            Request<OrganizationsPage> request = internalClient.users().getOrganizations(userId, filter);
            OrganizationsPage response = request.execute();

            orgs.addAll(response.getItems());

            return response;
        });

        return orgs;
    }

    public void addOrganizationRolesToUser(Uid uid, Map<String, List<String>> orgRoles) throws Auth0Exception {
        for (Map.Entry<String, List<String>> entry : orgRoles.entrySet()) {
            withAuth(() -> {
                Roles roles = new Roles(entry.getValue());
                Request<Void> request = internalClient.organizations().addRoles(entry.getKey(), uid.getUidValue(), roles);
                return request.execute();
            });
        }
    }

    public void removeOrganizationRolesToUser(Uid uid, Map<String, List<String>> orgRoles) throws Auth0Exception {
        for (Map.Entry<String, List<String>> entry : orgRoles.entrySet()) {
            withAuth(() -> {
                Roles roles = new Roles(entry.getValue());
                Request<Void> request = internalClient.organizations().deleteRoles(entry.getKey(), uid.getUidValue(), roles);
                return request.execute();
            });
        }
    }

    public Map<String, List<String>> getOrganizationRolesForUser(String userId) throws Auth0Exception {
        Map<String, List<String>> orgRoles = new HashMap<>();

        List<Organization> orgs = getOrganizationsForUser(userId);
        for (Organization org : orgs) {
            withAuthPaging(new PageFilter(), 0, 50, (filter, ignore) -> {
                Request<RolesPage> request = internalClient.organizations().getRoles(org.getId(), userId, filter);
                RolesPage response = request.execute();

                orgRoles.put(org.getId(),
                        response.getItems().stream().map(role -> role.getId()).collect(Collectors.toList()));

                return response;
            });
        }

        return orgRoles;
    }

    public void addPermissionsToUser(Uid uid, List<Permission> permissions) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.users().addPermissions(uid.getUidValue(), permissions);
            return request.execute();
        });
    }

    public void removePermissionsToUser(Uid uid, List<Permission> permissions) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.users().removePermissions(uid.getUidValue(), permissions);
            return request.execute();
        });
    }

    public List<Permission> getPermissionsForUser(String userId) throws Auth0Exception {
        List<Permission> permissions = new ArrayList<>();

        withAuthPaging(new PageFilter(), 0, 50, (filter, ignore) -> {
            Request<PermissionsPage> request = internalClient.users().listPermissions(userId, filter);
            PermissionsPage response = request.execute();

            permissions.addAll(response.getItems());

            return response;
        });

        return permissions;
    }

    // Role

    public Role createRole(Role newRole) throws Auth0Exception {
        return withAuth(() -> {
            Request<Role> request = internalClient.roles().create(newRole);
            Role response = request.execute();
            return response;
        });
    }

    public void updateRole(Uid uid, Role patchRole) throws Auth0Exception {
        withAuth(() -> {
            Request<Role> request = internalClient.roles().update(uid.getUidValue(), patchRole);
            return request.execute();
        });
    }

    public void deleteRole(Uid uid) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.roles().delete(uid.getUidValue());
            return request.execute();
        });
    }

    public Role getRoleByUid(String userId) throws Auth0Exception {
        return withAuth(() -> {
            Request<Role> request = internalClient.roles().get(userId);
            Role role = request.execute();
            return role;
        });
    }

    public List<Role> getRoleByName(String roleName) throws Auth0Exception {
        return withAuth(() -> {
            RolesFilter filter = new RolesFilter().withPage(0, 2)
                    .withName(roleName);

            Request<RolesPage> request = internalClient.roles().list(filter);
            RolesPage response = request.execute();
            return response.getItems();
        });
    }

    public int getRoles(OperationOptions options, ResultHandlerFunction<Role, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        RolesFilter rolesFilter = new RolesFilter();

        return withAuthPaging(rolesFilter, pageInitialOffset, pageSize, (filter, skipCount) -> {
            Request<RolesPage> request = internalClient.roles().list(filter);
            RolesPage response = request.execute();

            int count = 0;
            for (Role u : response.getItems()) {
                if (count < skipCount) {
                    count++;
                    continue;
                }

                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    public void addPermissionsToRole(Uid uid, List<Permission> permissions) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.roles().addPermissions(uid.getUidValue(), permissions);
            return request.execute();
        });
    }

    public void removePermissionsToRole(Uid uid, List<Permission> permissions) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.roles().removePermissions(uid.getUidValue(), permissions);
            return request.execute();
        });
    }

    public List<Permission> getPermissionsForRole(String roleId) throws Auth0Exception {
        List<Permission> permissions = new ArrayList<>();

        withAuthPaging(new PageFilter(), 0, 50, (filter, ignore) -> {
            Request<PermissionsPage> request = internalClient.roles().listPermissions(roleId, filter);
            PermissionsPage response = request.execute();

            permissions.addAll(response.getItems());

            return response;
        });

        return permissions;
    }

    // Organization

    public Organization createOrganization(Organization newOrg) throws Auth0Exception {
        return withAuth(() -> {
            Request<Organization> request = internalClient.organizations().create(newOrg);
            Organization response = request.execute();
            return response;
        });
    }

    public void updateOrganization(Uid uid, Organization patchOrg) throws Auth0Exception {
        withAuth(() -> {
            Request<Organization> request = internalClient.organizations().update(uid.getUidValue(), patchOrg);
            return request.execute();
        });
    }

    public void deleteOrganization(Uid uid) throws Auth0Exception {
        withAuth(() -> {
            Request request = internalClient.organizations().delete(uid.getUidValue());
            return request.execute();
        });
    }

    public Organization getOrganizationByUid(String orgId) throws Auth0Exception {
        return withAuth(() -> {
            Request<Organization> request = internalClient.organizations().get(orgId);
            Organization org = request.execute();
            return org;
        });
    }

    public Organization getOrganizationByName(String orgName) throws Auth0Exception {
        return withAuth(() -> {
            Request<Organization> request = internalClient.organizations().getByName(orgName);
            Organization response = request.execute();
            return response;
        });
    }

    public int getOrganizations(OperationOptions options, ResultHandlerFunction<Organization, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        PageFilter orgsFilter = new PageFilter();

        return withAuthPaging(orgsFilter, pageInitialOffset, pageSize, (filter, skipCount) -> {
            Request<OrganizationsPage> request = internalClient.organizations().list(filter);
            OrganizationsPage response = request.execute();

            int count = 0;
            for (Organization u : response.getItems()) {
                if (count < skipCount) {
                    count++;
                    continue;
                }

                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    // Utilities
    protected <T extends BaseFilter> int withAuthPaging(T filter, int pageOffset, int pageSize, PageFunction<T, Page<?>> callback) throws Auth0Exception {
        withTotals(filter, true);

        PageInfo pageInfo = newPageInfo(pageOffset, pageSize);

        if (pageInfo.isRequestedFullPage()) {
            // Start from page 0 in Auth0
            int pageNumber = 0;
            int total = 0;

            while (true) {
                withPage(filter, pageNumber, pageSize);

                Page<?> result = withAuth(() -> {
                    Page<?> response = callback.apply(filter, 0);
                    return response;
                });

                total = result.getTotal();
                if (total == 0) {
                    // Not found
                    break;
                }

                if (hasNextPage(result)) {
                    pageNumber++;
                    continue;
                }
                break;
            }
            return total;

        } else {
            // Start from page 0 in Auth0, so need -1
            int pageNumber = pageInfo.initPage - 1;
            int total = 0;

            for (int i = 0; i < pageInfo.times; i++) {
                withPage(filter, pageNumber, pageSize);

                final int skipCount = i == 0 ? pageInfo.skipCount : 0;

                Page<?> result = withAuth(() -> {
                    Page<?> response = callback.apply(filter, skipCount);
                    return response;
                });

                total = result.getTotal();
                if (total == 0) {
                    // Not found
                    break;
                }

                if (hasNextPage(result)) {
                    pageNumber++;
                    continue;
                }
                break;
            }
            return total;
        }
    }

    protected static class PageInfo {
        public final int pageOffset;
        public final int initPage;
        public final int skipCount;
        public final int times;

        public PageInfo(int pageOffset, int initPage, int skipCount, int times) {
            this.pageOffset = pageOffset;
            this.initPage = initPage;
            this.skipCount = skipCount;
            this.times = times;
        }

        public boolean isRequestedFullPage() {
            return pageOffset == 0;
        }
    }

    protected static PageInfo newPageInfo(int pageOffset, int pageSize) {
        if (pageOffset == 0) {
            // Requested full page
            return new PageInfo(pageOffset, 1, 0, -1);

        } else if ((pageOffset + pageSize - 1) % pageSize == 0) {
            int initPage = (pageOffset + pageSize - 1) / pageSize;
            return new PageInfo(pageOffset, initPage, 0, 1);

        } else {
            int initPage = ((pageOffset + pageSize - 1) / pageSize);
            int skipCount = pageOffset - ((initPage - 1) * pageSize) -1;

            return new PageInfo(pageOffset, initPage, skipCount, 2);
        }
    }

    private void withTotals(BaseFilter filter, boolean includesTotal) {
        if (filter instanceof PageFilter) {
            ((PageFilter) filter).withTotals(includesTotal);

        } else if (filter instanceof QueryFilter) {
            ((QueryFilter) filter).withTotals(includesTotal);

        } else if (filter instanceof ConnectionFilter) {
            ((ConnectionFilter) filter).withTotals(includesTotal);
        }
    }

    private void withPage(BaseFilter filter, int pageNumber, int pageSize) {
        if (filter instanceof PageFilter) {
            ((PageFilter) filter).withPage(pageNumber, pageSize);

        } else if (filter instanceof QueryFilter) {
            ((QueryFilter) filter).withPage(pageNumber, pageSize);

        } else if (filter instanceof ConnectionFilter) {
            ((ConnectionFilter) filter).withPage(pageNumber, pageSize);
        }
    }

    protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
        boolean retried = false;

        // Refresh token if expired in advance
        refreshToken();

        while (true) {
            try {
                T response = callback.apply();
                return response;
            } catch (APIException e) {
                // If the api token is expired during paging process, refresh the token then retry
                if (!retried && e.getStatusCode() == 401) {
                    refreshToken(true);
                    retried = true;
                    continue;
                }
                throw e;
            }
        }
    }

    @FunctionalInterface
    interface APIFunction<Result> {
        public Result apply() throws Auth0Exception;
    }

    @FunctionalInterface
    interface PageFunction<One, Result> {
        public Result apply(One one, int skipCount) throws Auth0Exception;
    }

    @FunctionalInterface
    public interface ResultHandlerFunction<One, Result> {
        public Result apply(One one) throws Auth0Exception;
    }

    private static boolean hasNextPage(Page<?> page) {
        Integer length = page.getLength();
        if (length == null) {
            return false;
        }
        int remains = (page.getTotal() - (page.getStart() + length));
        return remains > 0;
    }
}
