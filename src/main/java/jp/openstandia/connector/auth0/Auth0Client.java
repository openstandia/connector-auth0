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

        if (this.configuration.getConnectionTimeoutInSeconds() != null) {
            httpOptions.setConnectTimeout(this.configuration.getConnectionTimeoutInSeconds());
        }
        if (this.configuration.getReadTimeoutInSeconds() != null) {
            httpOptions.setReadTimeout(this.configuration.getReadTimeoutInSeconds());
        }
        if (this.configuration.getMaxRetries() != null) {
            httpOptions.setManagementAPIMaxRetries(this.configuration.getMaxRetries());
        }

        // HTTP Proxy
        if (StringUtil.isNotEmpty(this.configuration.getHttpProxyHost())) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(this.configuration.getHttpProxyHost(), this.configuration.getHttpProxyPort()));
            ProxyOptions proxyOptions = new ProxyOptions(proxy);
            httpOptions.setProxyOptions(proxyOptions);
        }

        // Setup client
        refreshToken();
        internalClient = new ManagementAPI(this.configuration.getDomain(), tokenHolder.getAccessToken(), httpOptions);

        // Verify we can access the API
        checkClient();
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
        if (configuration.getClientId() != null && configuration.getClientSecret() != null) {
            if (isExpired(tokenHolder)) {
                final AuthAPI[] authAPI = new AuthAPI[1];
                configuration.getClientSecret().access(c -> {
                    authAPI[0] = new AuthAPI(configuration.getDomain(), configuration.getDomain(), String.valueOf(c));
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

    protected boolean isExpired(TokenHolder holder) {
        if (holder == null) {
            return true;
        }
        long expiresAt = holder.getExpiresAt().getTime();
        long now = new Date().getTime();

        if (expiresAt + (60 * 1000) > now) {
            LOG.ok("Detected the token is expired");
            return true;
        }

        return false;
    }

    // User

    public User createUser(User newUser) throws Auth0Exception {
        Request<User> request = internalClient.users().create(newUser);
        User response = request.execute();
        return response;
    }

    public void updateUser(Uid uid, User patchUser) throws Auth0Exception {
        Request<User> request = internalClient.users().update(uid.getUidValue(), patchUser);
        request.execute();
    }

    public void deleteUser(Uid uid) throws Auth0Exception {
        Request request = internalClient.users().delete(uid.getUidValue());
        request.execute();
    }

    public User getUserByUid(String userId, UserFilter filter) throws Auth0Exception {
        Request<User> request = internalClient.users().get(userId, filter);
        User user = request.execute();
        return user;
    }

    public List<User> getUserByNameAttr(String attrValue, UserFilter filter) throws Auth0Exception {
        attrValue = attrValue.replace("\"", "\\\"");
        filter.withPage(0, 2)
                .withQuery(configuration.getUsernameAttribute() + ":\"" + attrValue + "\"");

        Request<UsersPage> request = internalClient.users().list(filter);
        UsersPage response = request.execute();
        return response.getItems();
    }

    public List<User> getUserByEmail(String email, FieldsFilter filter) throws Auth0Exception {
        Request<List<User>> request = internalClient.users().listByEmail(email, filter);
        List<User> response = request.execute();
        return response;
    }

    public void getUsers(UserFilter userFilter, OperationOptions options, ResultHandlerFunction<User, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        paging(userFilter, pageInitialOffset, pageSize, (filter) -> {
            Request<UsersPage> request = internalClient.users().list(filter);
            UsersPage response = request.execute();

            for (User u : response.getItems()) {
                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    public void addRolesToUser(Uid uid, List<String> roleIds) throws Auth0Exception {
        Request request = internalClient.users().addRoles(uid.getUidValue(), roleIds);
        request.execute();
    }

    public void removeRolesToUser(Uid uid, List<String> roleIds) throws Auth0Exception {
        Request request = internalClient.users().removeRoles(uid.getUidValue(), roleIds);
        request.execute();
    }

    public List<Role> getRolesForUser(String userId) throws Auth0Exception {
        List<Role> roles = new ArrayList<>();

        paging(new PageFilter(), 0, 50, (filter) -> {
            Request<RolesPage> request = internalClient.users().listRoles(userId, filter);
            RolesPage response = request.execute();

            roles.addAll(roles);

            return response;
        });

        return roles;
    }

    public void addOrganizationsToUser(Uid uid, List<String> orgIds) throws Auth0Exception {
        Members members = new Members(Stream.of(uid.getUidValue()).collect(Collectors.toList()));
        // Unfortunately, we need to call this API per organization
        for (String orgId : orgIds) {
            Request request = internalClient.organizations().addMembers(orgId, members);
            request.execute();
        }
    }

    public void removeOrganizationsToUser(Uid uid, List<String> orgIds) throws Auth0Exception {
        Members members = new Members(Stream.of(uid.getUidValue()).collect(Collectors.toList()));
        // Unfortunately, we need to call this API per organization
        for (String orgId : orgIds) {
            Request request = internalClient.organizations().deleteMembers(orgId, members);
            request.execute();
        }
    }

    public List<Organization> getOrganizationsForUser(String userId) throws Auth0Exception {
        List<Organization> orgs = new ArrayList<>();

        paging(new PageFilter(), 0, 50, (filter) -> {
            Request<OrganizationsPage> request = internalClient.users().getOrganizations(userId, filter);
            OrganizationsPage response = request.execute();

            orgs.addAll(response.getItems());

            return response;
        });

        return orgs;
    }

    public void addOrganizationRolesToUser(Uid uid, Map<String, List<String>> orgRoles) {
        for (Map.Entry<String, List<String>> entry : orgRoles.entrySet()) {
            Roles roles = new Roles(entry.getValue());
            internalClient.organizations().addRoles(entry.getKey(), uid.getUidValue(), roles);
        }
    }

    public void removeOrganizationRolesToUser(Uid uid, Map<String, List<String>> orgRoles) {
        for (Map.Entry<String, List<String>> entry : orgRoles.entrySet()) {
            Roles roles = new Roles(entry.getValue());
            internalClient.organizations().deleteRoles(entry.getKey(), uid.getUidValue(), roles);
        }
    }

    public Map<String, List<String>> getOrganizationRolesForUser(String userId) throws Auth0Exception {
        Map<String, List<String>> orgRoles = new HashMap<>();

        List<Organization> orgs = getOrganizationsForUser(userId);
        for (Organization org : orgs) {
            paging(new PageFilter(), 0, 50, (filter) -> {
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
        Request request = internalClient.users().addPermissions(uid.getUidValue(), permissions);
        request.execute();
    }

    public void removePermissionsToUser(Uid uid, List<Permission> permissions) throws Auth0Exception {
        Request request = internalClient.users().removePermissions(uid.getUidValue(), permissions);
        request.execute();
    }

    public List<Permission> getPermissionsForUser(String userId) throws Auth0Exception {
        List<Permission> roles = new ArrayList<>();

        paging(new PageFilter(), 0, 50, (filter) -> {
            Request<PermissionsPage> request = internalClient.users().listPermissions(userId, filter);
            PermissionsPage response = request.execute();

            roles.addAll(roles);

            return response;
        });

        return roles;
    }

    // Role

    public Role createRole(Role newRole) throws Auth0Exception {
        Request<Role> request = internalClient.roles().create(newRole);
        Role response = request.execute();
        return response;
    }

    public void updateRole(Uid uid, Role patchRole) throws Auth0Exception {
        Request<Role> request = internalClient.roles().update(uid.getUidValue(), patchRole);
        request.execute();
    }

    public void deleteRole(Uid uid) throws Auth0Exception {
        Request request = internalClient.roles().delete(uid.getUidValue());
        request.execute();
    }

    public Role getRoleByUid(String userId) throws Auth0Exception {
        Request<Role> request = internalClient.roles().get(userId);
        Role role = request.execute();
        return role;
    }

    public List<Role> getRoleByName(String roleName) throws Auth0Exception {
        RolesFilter filter = new RolesFilter().withPage(0, 2)
                .withName(roleName);

        Request<RolesPage> request = internalClient.roles().list(filter);
        RolesPage response = request.execute();
        return response.getItems();
    }

    public void getRoles(OperationOptions options, ResultHandlerFunction<Role, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        RolesFilter rolesFilter = new RolesFilter();

        paging(rolesFilter, pageInitialOffset, pageSize, (filter) -> {
            Request<RolesPage> request = internalClient.roles().list(filter);
            RolesPage response = request.execute();

            for (Role u : response.getItems()) {
                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    public void addPermissionsToRole(Uid uid, List<Permission> permissions) throws Auth0Exception {
        Request request = internalClient.roles().addPermissions(uid.getUidValue(), permissions);
        request.execute();
    }

    public void removePermissionsToRole(Uid uid, List<Permission> permissions) throws Auth0Exception {
        Request request = internalClient.roles().removePermissions(uid.getUidValue(), permissions);
        request.execute();
    }

    public List<Permission> getPermissionsForRole(String roleId) throws Auth0Exception {
        List<Permission> roles = new ArrayList<>();

        paging(new PageFilter(), 0, 50, (filter) -> {
            Request<PermissionsPage> request = internalClient.roles().listPermissions(roleId, filter);
            PermissionsPage response = request.execute();

            roles.addAll(roles);

            return response;
        });

        return roles;
    }

    // Organization

    public Organization createOrganization(Organization newOrg) throws Auth0Exception {
        Request<Organization> request = internalClient.organizations().create(newOrg);
        Organization response = request.execute();
        return response;
    }

    public void updateOrganization(Uid uid, Organization patchOrg) throws Auth0Exception {
        Request<Organization> request = internalClient.organizations().update(uid.getUidValue(), patchOrg);
        request.execute();
    }

    public void deleteOrganization(Uid uid) throws Auth0Exception {
        Request request = internalClient.organizations().delete(uid.getUidValue());
        request.execute();
    }

    public Organization getOrganizationByUid(String orgId) throws Auth0Exception {
        Request<Organization> request = internalClient.organizations().get(orgId);
        Organization org = request.execute();
        return org;
    }

    public Organization getOrganizationByName(String orgName) throws Auth0Exception {
        Request<Organization> request = internalClient.organizations().getByName(orgName);
        Organization response = request.execute();
        return response;
    }

    public void getOrganizations(OperationOptions options, ResultHandlerFunction<Organization, Boolean> resultsHandler) throws Auth0Exception {
        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        PageFilter rolesFilter = new PageFilter();

        paging(rolesFilter, pageInitialOffset, pageSize, (filter) -> {
            Request<OrganizationsPage> request = internalClient.organizations().list(filter);
            OrganizationsPage response = request.execute();

            for (Organization u : response.getItems()) {
                Boolean next = resultsHandler.apply(u);
                if (!next) {
                    break;
                }
            }

            return response;
        });
    }

    // Utilities

    private <T extends PageFilter> void paging(T filter, int initialOffset, int pageSize, PageFunction<T, Page<?>> callback) throws Auth0Exception {
        int offset = initialOffset;
        boolean retried = false;

        filter.withTotals(true);

        while (true) {
            try {
                filter.withPage(offset, pageSize);

                Page<?> response = callback.apply(filter);
                if (hasNextPage(response)) {
                    offset++;
                    retried = false;
                    continue;
                }
                break;
            } catch (APIException e) {
                // If the api token is expired during paging process, refresh the token then retry
                if (!retried && e.getStatusCode() == 401 && e.getError().equals("Invalid tokens.")) {
                    refreshToken();
                    retried = true;
                    continue;
                }
                throw e;
            }
        }
    }

    private <T extends QueryFilter> void paging(T filter, int initialOffset, int pageSize, PageFunction<T, Page<?>> callback) throws Auth0Exception {
        int offset = initialOffset;
        boolean retried = false;

        filter.withTotals(true);

        while (true) {
            try {
                filter.withPage(offset, pageSize);

                Page<?> response = callback.apply(filter);
                if (hasNextPage(response)) {
                    offset++;
                    retried = false;
                    continue;
                }
                break;
            } catch (APIException e) {
                // If the api token is expired during paging process, refresh the token then retry
                if (!retried && e.getStatusCode() == 401 && e.getError().equals("Invalid tokens.")) {
                    refreshToken();
                    retried = true;
                    continue;
                }
                throw e;
            }
        }
    }

    @FunctionalInterface
    interface PageFunction<One, Result> {
        public Result apply(One one) throws Auth0Exception;
    }

    @FunctionalInterface
    interface ResultHandlerFunction<One, Result> {
        public Result apply(One one) throws Auth0Exception;
    }

    private static boolean hasNextPage(Page<?> page) {
        int remains = (page.getTotal() - page.getStart() + page.getLimit());
        return remains > 0;
    }
}
