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

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.PageFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.RolesPage;
import com.auth0.net.Request;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Uid;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.AdminListGroupsForUserIterable;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersInGroupIterable;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static jp.openstandia.connector.auth0.Auth0Utils.checkCognitoResult;
import static jp.openstandia.connector.auth0.Auth0Utils.paging;

public class Auth0AssociationHandler {

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    private final Auth0Configuration configuration;
    private final CognitoIdentityProviderClient client;
    private final ManagementAPI client2;

    public Auth0AssociationHandler(Auth0Configuration configuration, CognitoIdentityProviderClient client) {
        this.configuration = configuration;
        this.client = client;
        this.client2 = null;
    }

    public Auth0AssociationHandler(Auth0Configuration configuration, ManagementAPI client) {
        this.configuration = configuration;
        this.client = null;
        this.client2 = client;
    }

    public void addRolesToUser(Uid uid, List<Object> addRoles) throws Auth0Exception {
        if (addRoles != null && !addRoles.isEmpty()) {
            List<String> roles = addRoles.stream().map(r -> r.toString()).collect(Collectors.toList());
            Request request = client2.users().addRoles(uid.getUidValue(), roles);
            request.execute();
        }
    }

    public void updateRolesToUser(Uid uid, List<Object> addRoles, List<Object> removeGroups) throws Auth0Exception {
        if (addRoles != null && !addRoles.isEmpty()) {
            List<String> roles = addRoles.stream().map(r -> r.toString()).collect(Collectors.toList());
            Request request = client2.users().addRoles(uid.getUidValue(), roles);
            request.execute();
        }
        if (removeGroups != null && !removeGroups.isEmpty()) {
            List<String> roles = addRoles.stream().map(r -> r.toString()).collect(Collectors.toList());
            Request request = client2.users().removeRoles(uid.getUidValue(), roles);
            request.execute();
        }
    }

    private void removeUserFromGroup(String username, String groupName) {
        AdminRemoveUserFromGroupRequest.Builder request = AdminRemoveUserFromGroupRequest.builder()
                .userPoolId(configuration.getDomain())
                .username(username)
                .groupName(groupName);

        AdminRemoveUserFromGroupResponse result = client.adminRemoveUserFromGroup(request.build());

        checkCognitoResult(result, "AdminRemoveUserFromGroup");
    }

    public void removeAllUsers(String groupName) {
        getUsers(groupName, u -> removeUserFromGroup(u.username(), groupName));
    }

    public List<String> getUsersInGroup(String groupName) {
        List<String> users = new ArrayList<>();
        getUsers(groupName, u -> {
            users.add(u.username());
        });
        return users;
    }


    private interface UserHandler {
        void handle(UserType user);
    }

    void getUsers(String groupName, UserHandler handler) {
        ListUsersInGroupRequest.Builder request = ListUsersInGroupRequest.builder()
                .userPoolId(configuration.getDomain())
                .groupName(groupName);

        ListUsersInGroupIterable result = client.listUsersInGroupPaginator(request.build());

        result.forEach(r -> r.users().stream().forEach(u -> handler.handle(u)));
    }

    public List<String> getRolesForUser(Auth0Connector connector, String userId) throws Auth0Exception {
        int pageInitialOffset = 0;
        int pageSize = 50;

        List<String> roles = new ArrayList<>();

        paging(connector, pageInitialOffset, pageSize, (offset, size) -> {
            PageFilter filter = new PageFilter()
                    .withTotals(true)
                    .withPage(offset, size);
            Request<RolesPage> request = client2.users().listRoles(userId, filter);
            RolesPage response = request.execute();

            for (Role role : response.getItems()) {
                roles.add(role.getId());
            }

            return response;
        });

        return roles;
    }

    private interface GroupHandler {
        void handle(GroupType group);
    }

    private void getGroups(String userName, GroupHandler handler) {
        AdminListGroupsForUserRequest.Builder request = AdminListGroupsForUserRequest.builder()
                .userPoolId(configuration.getDomain())
                .username(userName);

        AdminListGroupsForUserIterable result = client.adminListGroupsForUserPaginator(request.build());

        result.forEach(r -> r.groups().stream().forEach(g -> handler.handle(g)));
    }
}
