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
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static jp.openstandia.connector.auth0.Auth0Utils.*;

public class Auth0RoleHandler {

    public static final ObjectClass ROLE_OBJECT_CLASS = new ObjectClass("Role");

    private static final Log LOGGER = Log.getLog(Auth0RoleHandler.class);

    // Unique and unchangeable
    private static final String ATTR_ROLE_ID = "roleId";

    // Unique and changeable
    private static final String ATTR_ROLE_NAME = "name";

    // Attributes
    private static final String ATTR_DESCRIPTION = "description";

    // Association
    // Permissions are represented as the following JSON Object array.
    // [
    //   {
    //     "resource_server_identifier": "https://myapi.example.com"
    //     "permission_name": "read:foo"
    //   },
    //   {
    //     "resource_server_identifier": "https://myapi.example.com"
    //     "permission_name": "write:foo"
    //   }
    // ]
    //
    // Instead of it, we represent them as the string array in thins connector.
    // [
    //   "https://myapi.example.com#read:foo",
    //   "https://myapi.example.com#write:foo"
    // ]
    //
    private static final String ATTR_PERMISSIONS = "permissions";

    private final Auth0Configuration configuration;
    private final Auth0Client client;
    private final Map<String, AttributeInfo> schema;
    private final Auth0AssociationHandler associationHandler;

    public Auth0RoleHandler(Auth0Configuration configuration, Auth0Client client, Map<String, AttributeInfo> schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.associationHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getSchema(Auth0Configuration config) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(ROLE_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(true)
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_ROLE_ID)
                .build());
        // __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .setNativeName(ATTR_ROLE_NAME)
                .build());

        // Standard Attributes
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DESCRIPTION)
                .build());

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PERMISSIONS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        ObjectClassInfo roleSchemaInfo = builder.build();

        LOGGER.info("The constructed Role schema: {0}", roleSchemaInfo);

        return roleSchemaInfo;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/post_roles
     *
     * @param attributes
     * @return
     * @throws Auth0Exception
     */
    public Uid createRole(Set<Attribute> attributes) throws Auth0Exception {
        Role newRole = new Role();
        List<Object> permissions = null;

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newRole.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newRole.setDescription(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_PERMISSIONS)) {
                permissions = attr.getValue();

            } else {
                throwInvalidSchema(attr.getName());
            }
        }

        Role response = client.createRole(newRole);

        Uid newUid = new Uid(response.getId(), new Name(response.getName()));

        // We need to call another API to add/remove permissions for this role.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Auth0 data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        associationHandler.addPermissionsToRole(newUid, permissions);

        return newUid;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/patch_roles_by_id
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     * @throws Auth0Exception
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws Auth0Exception {
        Role patchRole = new Role();
        List<Object> permissionsToAdd = null;
        List<Object> permissionsToRemove = null;

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Name.NAME)) {
                patchRole.setName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_DESCRIPTION)) {
                patchRole.setDescription(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_PERMISSIONS)) {
                permissionsToAdd = delta.getValuesToAdd();
                permissionsToRemove = delta.getValuesToRemove();

            } else {
                throwInvalidSchema(delta.getName());
            }
        }

        client.updateRole(uid, patchRole);

        // We need to call another API to add/remove role for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Auth0 data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        associationHandler.updatePermissionsToRole(uid, permissionsToAdd, permissionsToRemove);

        return null;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/delete_roles_by_id
     *
     * @param uid
     * @param options
     * @throws Auth0Exception
     */
    public void deleteRole(Uid uid, OperationOptions options) throws Auth0Exception {
        client.deleteRole(uid);
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/get_roles
     *
     * @param filter
     * @param resultsHandler
     * @param options
     * @throws Auth0Exception
     */
    public void getRoles(Auth0Filter filter,
                         ResultsHandler resultsHandler, OperationOptions options) throws Auth0Exception {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null) {
            if (filter.isByName()) {
                // Filter by __NANE__
                getRoleByName(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            } else {
                // Filter by __UID__
                getRoleByUid(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            }
            return;
        }

        client.getRoles(options, (role) -> resultsHandler.handle(toConnectorObject(role, attributesToGet, allowPartialAttributeValues)));
    }

    private void getRoleByName(String roleName,
                               ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        List<Role> response = client.getRoleByName(roleName);

        for (Role role : response) {
            resultsHandler.handle(toConnectorObject(role, attributesToGet, allowPartialAttributeValues));
        }
    }

    private void getRoleByUid(String roleId,
                              ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        Role role = client.getRoleByUid(roleId);

        resultsHandler.handle(toConnectorObject(role, attributesToGet, allowPartialAttributeValues));
    }

    private ConnectorObject toConnectorObject(Role role, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(ROLE_OBJECT_CLASS)
                .setUid(role.getId())
                .setName(role.getName());

        if (shouldReturn(attributesToGet, ATTR_DESCRIPTION)) {
            if (role.getDescription() != null) {
                builder.addAttribute(ATTR_DESCRIPTION, role.getDescription());
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching association
            LOGGER.ok("Suppress fetching association because return partial attribute values is requested");

            if (shouldReturn(attributesToGet, ATTR_PERMISSIONS)) {
                builder.addAttribute(createIncompleteAttribute(ATTR_PERMISSIONS));
            }
        } else {
            if (attributesToGet == null) {
                // Suppress fetching association default
                LOGGER.ok("Suppress fetching association because returned by default is true");

            } else {
                if (shouldReturn(attributesToGet, ATTR_PERMISSIONS)) {
                    // Fetch permissions
                    LOGGER.ok("Fetching permissions because attributes to get is requested");

                    List<Permission> permissions = associationHandler.getPermissionsForRole(role.getId());
                    builder.addAttribute(ATTR_PERMISSIONS, toTextPermissions(permissions));
                }
            }
        }

        return builder.build();
    }
}
