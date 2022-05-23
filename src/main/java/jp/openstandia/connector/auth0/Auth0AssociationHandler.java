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

import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Permission;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.organizations.Organization;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Uid;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Auth0AssociationHandler {

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    private final Auth0Configuration configuration;
    private final Auth0Client client;

    public Auth0AssociationHandler(Auth0Configuration configuration, Auth0Client client) {
        this.configuration = configuration;
        this.client = client;
    }

    // For User

    public void addRolesToUser(Uid uid, List<Object> roles) throws Auth0Exception {
        if (isNotEmpty(roles)) {
            client.addRolesToUser(uid, toRoles(roles));
        }
    }

    public void updateRolesToUser(Uid uid, List<Object> rolesToAdd, List<Object> rolesToRemove) throws Auth0Exception {
        if (isNotEmpty(rolesToAdd)) {
            client.addRolesToUser(uid, toRoles(rolesToAdd));
        }
        if (isNotEmpty(rolesToRemove)) {
            client.removeRolesToUser(uid, toRoles(rolesToRemove));
        }
    }

    public List<Role> getRolesForUser(String userId) throws Auth0Exception {
        return client.getRolesForUser(userId);
    }

    public void addOrganizationsToUser(Uid uid, List<Object> orgs) throws Auth0Exception {
        if (isNotEmpty(orgs)) {
            client.addOrganizationsToUser(uid, toOrgs(orgs));
        }
    }

    public void updateOrganizationsToUser(Uid uid, List<Object> orgsToAdd, List<Object> orgsToRemove) throws Auth0Exception {
        if (isNotEmpty(orgsToAdd)) {
            client.addOrganizationsToUser(uid, toOrgs(orgsToAdd));
        }
        if (isNotEmpty(orgsToRemove)) {
            client.removeOrganizationsToUser(uid, toOrgs(orgsToRemove));
        }
    }

    public List<Organization> getOrganizationsForUser(String userId) throws Auth0Exception {
        return client.getOrganizationsForUser(userId);
    }

    public void addOrganizationRolesToUser(Uid uid, List<Object> orgRoles) {
        if (isNotEmpty(orgRoles)) {
            client.addOrganizationRolesToUser(uid, toOrgRoles(orgRoles));
        }
    }

    public void updateOrganizationRolesToUser(Uid uid, List<Object> orgRolesToAdd, List<Object> orgRolesToRemove) {
        if (isNotEmpty(orgRolesToAdd)) {
            client.addOrganizationRolesToUser(uid, toOrgRoles(orgRolesToAdd));
        }
        if (isNotEmpty(orgRolesToRemove)) {
            client.removeOrganizationRolesToUser(uid, toOrgRoles(orgRolesToRemove));
        }
    }

    public Map<String, List<String>> getOrganizationRolesForUser(String userId) throws Auth0Exception {
        return client.getOrganizationRolesForUser(userId);
    }

    public void addPermissionsToUser(Uid uid, List<Object> textPermissions) throws Auth0Exception {
        if (isNotEmpty(textPermissions)) {
            client.addPermissionsToUser(uid, toPermissions(textPermissions));
        }
    }

    public void updatePermissionsToUser(Uid uid, List<Object> permissionsToAdd, List<Object> permissionsToRemove) throws Auth0Exception {
        if (isNotEmpty(permissionsToAdd)) {
            client.addPermissionsToUser(uid, toPermissions(permissionsToAdd));
        }
        if (isNotEmpty(permissionsToRemove)) {
            client.removePermissionsToUser(uid, toPermissions(permissionsToRemove));
        }
    }

    public List<Permission> getPermissionsForUser(String userId) throws Auth0Exception {
        return client.getPermissionsForUser(userId);
    }

    // For Role

    public void addPermissionsToRole(Uid uid, List<Object> textPermissions) throws Auth0Exception {
        if (isNotEmpty(textPermissions)) {
            client.addPermissionsToRole(uid, toPermissions(textPermissions));
        }
    }

    public void updatePermissionsToRole(Uid uid, List<Object> permissionsToAdd, List<Object> permissionsToRemove) throws Auth0Exception {
        if (isNotEmpty(permissionsToAdd)) {
            client.addPermissionsToRole(uid, toPermissions(permissionsToAdd));
        }
        if (isNotEmpty(permissionsToRemove)) {
            client.removePermissionsToRole(uid, toPermissions(permissionsToAdd));
        }
    }

    public List<Permission> getPermissionsForRole(String roleId) throws Auth0Exception {
        return client.getPermissionsForRole(roleId);
    }

    // Utilities

    private static List<String> toRoles(List<Object> roles) {
        return roles.stream().map(r -> r.toString()).collect(Collectors.toList());
    }

    private static List<Permission> toPermissions(List<Object> textPermissions) {
        return textPermissions.stream().map(p -> {
            String[] idAndScope = p.toString().split("#");
            if (idAndScope.length != 2) {
                throw new InvalidAttributeValueException("Invalid permission format: " + p);
            }
            Permission permission = new Permission();
            permission.setResourceServerId(idAndScope[0]);
            permission.setName(idAndScope[1]);

            return permission;
        }).collect(Collectors.toList());
    }

    private static List<String> toOrgs(List<Object> orgs) {
        return orgs.stream().map(r -> r.toString()).collect(Collectors.toList());
    }

    private static Map<String, List<String>> toOrgRoles(List<Object> orgRoles) {
        Map<String, List<String>> result = new HashMap<>();
        for (Object o : orgRoles) {
            String[] split = o.toString().split(":");
            if (split.length != 2) {
                throw new InvalidAttributeValueException("Invalid organization_roles format: " + o.toString());
            }

            List<String> roles = result.get(split[0]);
            if (roles == null) {
                roles = new ArrayList<>();
                result.put(split[0], roles);
            }
            roles.add(split[1]);
        }
        return result;
    }

    private boolean isNotEmpty(List list) {
        return list != null && !list.isEmpty();
    }
}
