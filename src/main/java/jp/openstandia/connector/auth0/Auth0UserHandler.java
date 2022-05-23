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

import com.auth0.client.mgmt.filter.FieldsFilter;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Permission;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.organizations.Organization;
import com.auth0.json.mgmt.users.User;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.auth0.Auth0Utils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.PASSWORD_NAME;

public class Auth0UserHandler {

    public static final ObjectClass USER_OBJECT_CLASS = new ObjectClass("User");

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    // Unique and unchangeable
    // Used as __NAME__ by configuration
    private static final String ATTR_USER_ID = "user_id";

    // Standard Attributes
    // Used as __NAME__ by configuration
    private static final String ATTR_EMAIL = "email";
    private static final String ATTR_NICKNAME = "nickname";
    // Used as __NAME__ by configuration
    private static final String ATTR_PHONE_NUMBER = "phone_number";
    private static final String ATTR_GIVEN_NAME = "given_name";
    private static final String ATTR_FAMILY_NAME = "family_name";
    // Full name e.g. "John Doe"
    private static final String ATTR_NAME = "name";
    // Picture URI e.g. "https://secure.gravatar.com/avatar/15626c5e0c749cb912f9d1ad48dba440?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png"
    private static final String ATTR_PICTURE = "picture";
    // Username e.g. "johndoe"
    // Only valid if the connection requires a username
    // Used as __NAME__ by configuration
    private static final String ATTR_USERNAME = "username";
    // Whether this email address is verified (true) or unverified (false).
    // User will receive a verification email after creation if email_verified is false or not specified.
    private static final String ATTR_EMAIL_VERIFIED = "email_verified";
    // Whether this phone number has been verified (true) or not (false).
    private static final String ATTR_PHONE_VERIFIED = "phone_verified";

    // Operation
    // Whether the user will receive a verification email after creation (true) or no email (false).
    // Overrides behavior of email_verified parameter.
    private static final String ATTR_VERIFY_EMAIL = "verify_email";
    // Whether this user will receive a text after changing the phone number (true) or no text (false).
    // Only valid when changing phone number.
    private static final String ATTR_VERIFY_PHONE_NUMBER = "verify_phone_number";

    // Metadata
    // Whether this user was blocked by an administrator (true) or not (false)
    // Used as __ENABLED__
    private static final String ATTR_BLOCKED = "blocked";
    private static final String ATTR_CONNECTION = "connection";
    private static final String ATTR_IDENTITIES = "identities";
    private static final String ATTR_CREATED_AT = "created_at";
    private static final String ATTR_UPDATED_AT = "updated_at";
    // Can't get from "Get a User" API
    // private static final String ATTR_MULTIFACTOR_LAST_MODIFIED = "multifactor_last_modified";
    private static final String ATTR_LAST_IP = "last_ip";
    private static final String ATTR_LAST_LOGIN = "last_login";
    private static final String ATTR_LOGINS_COUNT = "logins_count";

    // Association
    // Roles are represented as the list of role's id
    private static final String ATTR_ROLES = "roles";
    // Organizations are represented as the list of organization's id
    private static final String ATTR_ORGANIZATIONS = "organizations";
    // Organization Roles are represented as the list of "{orgId}:{roleId}"
    private static final String ATTR_ORGANIZATION_ROLES = "organization_roles";
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
    // Instead of it, we represent them as the string array in this connector.
    // [
    //   "https://myapi.example.com#read:foo",
    //   "https://myapi.example.com#write:foo"
    // ]
    //
    private static final String ATTR_PERMISSIONS = "permissions";

    // Password
    // Initial password for this user (mandatory only for auth0 connection strategy)
    private static final String ATTR_PASSWORD = PASSWORD_NAME;

    // Enable
    private static final String ATTR_ENABLE = ENABLE_NAME;

    // Allowed fields in users query to retrieve fields
    private static final Set<String> ALLOWED_FIELDS_SET = Stream.of(
            ATTR_PHONE_NUMBER,
            ATTR_EMAIL,
            ATTR_EMAIL_VERIFIED,
            ATTR_PICTURE,
            ATTR_USERNAME,
            ATTR_USER_ID,
            ATTR_NAME,
            ATTR_NICKNAME,
            ATTR_CREATED_AT,
            "identities",
            "app_metadata",
            "user_metadata",
            ATTR_LAST_IP,
            ATTR_LAST_LOGIN,
            ATTR_LOGINS_COUNT,
            ATTR_UPDATED_AT,
            ATTR_FAMILY_NAME,
            ATTR_GIVEN_NAME
    ).collect(Collectors.toSet());

    public static final Set<String> ALLOWED_NAME_ATTRS = Stream.of(
            ATTR_EMAIL,
            ATTR_PHONE_NUMBER,
            ATTR_USERNAME,
            ATTR_USER_ID
    ).collect(Collectors.toCollection(LinkedHashSet::new));

    private final Auth0Configuration configuration;
    private final Auth0Client client;
    private final Auth0AssociationHandler associationHandler;
    private final Map<String, AttributeInfo> schema;

    public Auth0UserHandler(Auth0Configuration configuration, Auth0Client client,
                            Map<String, AttributeInfo> schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.associationHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getSchema(Auth0Configuration config) {
        LOGGER.ok("User: {0}");

        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false)
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_USER_ID)
                        .build()
        );

        // __NAME__
        // CaseSensitive
        AttributeInfoBuilder usernameBuilder = AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true);
        String usernameAttr = config.getUsernameAttribute();
        usernameBuilder.setNativeName(usernameAttr);
        if (usernameAttr.equals(ATTR_USER_ID)) {
            // Unchangeable if user_id is used as __NAME__
            usernameBuilder.setUpdateable(true);
        }
        builder.addAttributeInfo(usernameBuilder.build());

        ALLOWED_NAME_ATTRS.stream()
                .filter(attr -> !attr.equals(usernameAttr) && !attr.equals(ATTR_USER_ID))
                .forEach(attr -> {
                    builder.addAttributeInfo(AttributeInfoBuilder.define(attr).build());
                });

        // __ENABLE__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        // __PASSWORD__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

        // Other attributes
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_NICKNAME).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_GIVEN_NAME).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_FAMILY_NAME).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_NAME).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PICTURE).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_EMAIL_VERIFIED)
                .setType(Boolean.class)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PHONE_VERIFIED)
                .setType(Boolean.class)
                .build());

        // Operation
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_VERIFY_EMAIL)
                .setType(Boolean.class)
                .setReadable(false)
                .setReturnedByDefault(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_VERIFY_PHONE_NUMBER)
                .setType(Boolean.class)
                .setReadable(false)
                .setReturnedByDefault(false)
                .build());

        // Metadata
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CONNECTION)
                .setRequired(true)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_IDENTITIES)
                .setCreateable(false)
                .setMultiValued(true)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CREATED_AT)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_UPDATED_AT)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
//        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_MULTIFACTOR_LAST_MODIFIED)
//                .setType(ZonedDateTime.class)
//                .setCreateable(false)
//                .setUpdateable(false)
//                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_LAST_LOGIN)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_LAST_IP)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_LOGINS_COUNT)
                .setType(Long.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ROLES)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ORGANIZATIONS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ORGANIZATION_ROLES)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PERMISSIONS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        ObjectClassInfo userSchemaInfo = builder.build();

        LOGGER.ok("The constructed User core schema: {0}", userSchemaInfo);

        return userSchemaInfo;
    }


    private static boolean isNameAttribute(Auth0Configuration configuration, String attrName) {
        return configuration.getUsernameAttribute().equals(attrName);
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/post_users
     *
     * @param attributes
     * @return
     */
    public Uid createUser(Set<Attribute> attributes) throws Auth0Exception {
        User newUser = new User();
        List<Object> roles = null;
        List<Object> orgs = null;
        List<Object> orgRoles = null;
        List<Object> permissions = null;

        for (Attribute attr : attributes) {
            // __NAME__
            if (attr.getName().equals(Name.NAME)) {
                if (isNameAttribute(configuration, ATTR_EMAIL)) {
                    newUser.setEmail(AttributeUtil.getAsStringValue(attr));
                } else if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
                    newUser.setPhoneNumber(AttributeUtil.getAsStringValue(attr));
                } else if (isNameAttribute(configuration, ATTR_USERNAME)) {
                    newUser.setUsername(AttributeUtil.getAsStringValue(attr));
                }
            }

            // Standard Attributes
            else if (attr.getName().equals(ATTR_EMAIL)) {
                newUser.setEmail(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_NICKNAME)) {
                newUser.setNickname(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_PHONE_NUMBER)) {
                newUser.setPhoneNumber(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_GIVEN_NAME)) {
                newUser.setGivenName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_FAMILY_NAME)) {
                newUser.setFamilyName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_NAME)) {
                newUser.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_PICTURE)) {
                newUser.setPicture(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_USERNAME)) {
                newUser.setUsername(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_EMAIL_VERIFIED)) {
                newUser.setEmailVerified(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_VERIFY_EMAIL)) {
                newUser.setVerifyEmail(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_PHONE_VERIFIED)) {
                newUser.setPhoneVerified(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_VERIFY_PHONE_NUMBER)) {
                newUser.setVerifyPhoneNumber(AttributeUtil.getBooleanValue(attr));
            }

            // Metadata
            else if (attr.getName().equals(OperationalAttributes.ENABLE_NAME)) {
                newUser.setBlocked(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_CONNECTION)) {
                newUser.setConnection(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeUtil.getGuardedStringValue(attr).access(c -> {
                    newUser.setPassword(c);
                });
            }

            // Association
            else if (attr.getName().equals(ATTR_ROLES)) {
                roles = attr.getValue();

            } else if (attr.getName().equals(ATTR_ORGANIZATIONS)) {
                orgs = attr.getValue();

            } else if (attr.getName().equals(ATTR_ORGANIZATION_ROLES)) {
                orgRoles = attr.getValue();

            } else if (attr.getName().equals(ATTR_PERMISSIONS)) {
                permissions = attr.getValue();

            } else {
                if (!schema.containsKey(attr.getName())) {
                    throwInvalidSchema(attr.getName());
                }
            }
        }

        User response = client.createUser(newUser);

        Uid newUid = new Uid(response.getId(), new Name(response.getEmail()));

        // We need to call another API to add/remove roles/organizations/permissions for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Auth0 data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        associationHandler.addRolesToUser(newUid, roles);
        associationHandler.addOrganizationsToUser(newUid, orgs);
        associationHandler.addOrganizationRolesToUser(newUid, orgRoles);
        associationHandler.addPermissionsToRole(newUid, permissions);

        return newUid;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/patch_users_by_id
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws Auth0Exception {
        User modifyUser = new User();
        List<Object> rolesToAdd = null;
        List<Object> rolesToRemove = null;
        List<Object> orgsToAdd = null;
        List<Object> orgsToRemove = null;
        List<Object> orgRolesToAdd = null;
        List<Object> orgRolesToRemove = null;
        List<Object> permissionsToAdd = null;
        List<Object> permissionsToRemove = null;

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Uid.NAME)) {
                // Doesn't support to modify 'user_id'
                throwInvalidSchema(delta.getName());
            }

            // __NAME__
            else if (delta.getName().equals(Name.NAME)) {
                if (isNameAttribute(configuration, ATTR_EMAIL)) {
                    modifyUser.setEmail(AttributeDeltaUtil.getAsStringValue(delta));
                } else if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
                    modifyUser.setPhoneNumber(AttributeDeltaUtil.getAsStringValue(delta));
                } else if (isNameAttribute(configuration, ATTR_USERNAME)) {
                    modifyUser.setUsername(AttributeDeltaUtil.getAsStringValue(delta));
                }
            }

            // Standard Attributes
            else if (delta.getName().equals(ATTR_EMAIL)) {
                modifyUser.setEmail(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_NICKNAME)) {
                modifyUser.setNickname(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_PHONE_NUMBER)) {
                modifyUser.setPhoneNumber(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_GIVEN_NAME)) {
                modifyUser.setGivenName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_FAMILY_NAME)) {
                modifyUser.setFamilyName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_NAME)) {
                modifyUser.setName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_PICTURE)) {
                modifyUser.setPicture(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_USERNAME)) {
                modifyUser.setUsername(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_EMAIL_VERIFIED)) {
                modifyUser.setEmailVerified(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_VERIFY_EMAIL)) {
                modifyUser.setVerifyEmail(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_PHONE_VERIFIED)) {
                modifyUser.setPhoneVerified(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_VERIFY_PHONE_NUMBER)) {
                modifyUser.setVerifyPhoneNumber(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_BLOCKED)) {
                modifyUser.setBlocked(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_CONNECTION)) {
                modifyUser.setConnection(AttributeDeltaUtil.getAsStringValue(delta));
            }

            // Metadata
            else if (delta.getName().equals(OperationalAttributes.ENABLE_NAME)) {
                modifyUser.setBlocked(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(ATTR_CONNECTION)) {
                modifyUser.setConnection(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeDeltaUtil.getGuardedStringValue(delta).access(c -> {
                    modifyUser.setPassword(c);
                });
            }

            // Association
            else if (delta.getName().equals(ATTR_ROLES)) {
                rolesToAdd = delta.getValuesToAdd();
                rolesToRemove = delta.getValuesToRemove();

            } else if (delta.getName().equals(ATTR_ORGANIZATIONS)) {
                orgsToAdd = delta.getValuesToAdd();
                orgsToRemove = delta.getValuesToRemove();

            } else if (delta.getName().equals(ATTR_ORGANIZATION_ROLES)) {
                orgRolesToAdd = delta.getValuesToAdd();
                orgRolesToRemove = delta.getValuesToRemove();

            } else if (delta.getName().equals(ATTR_PERMISSIONS)) {
                permissionsToAdd = delta.getValuesToAdd();
                permissionsToRemove = delta.getValuesToRemove();

            } else {
                if (!schema.containsKey(delta.getName())) {
                    throwInvalidSchema(delta.getName());
                }
            }
        }

        client.updateUser(uid, modifyUser);

        // We need to call another API to add/remove role for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Auth0 data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        associationHandler.updateRolesToUser(uid, rolesToAdd, rolesToRemove);
        associationHandler.updateOrganizationsToUser(uid, orgsToAdd, orgsToRemove);
        associationHandler.updateOrganizationRolesToUser(uid, orgRolesToAdd, orgRolesToRemove);
        associationHandler.updateRolesToUser(uid, permissionsToAdd, permissionsToRemove);

        return null;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/delete_users_by_id
     *
     * @param uid
     * @param options
     */
    public void deleteUser(Uid uid, OperationOptions options) throws Auth0Exception {
        client.deleteUser(uid);
    }

    public void getUsers(Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) throws Auth0Exception {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null) {
            if (filter.isByName()) {
                // Filter by __NANE__
                if (isNameAttribute(configuration, ATTR_EMAIL)) {
                    getUserByEmail(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
                } else {
                    getUserByNameAttr(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
                }
            } else {
                // Filter by __UID__
                getUserByUid(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            }
            return;
        }

        UserFilter userFilter = applyFieldsFilter(configuration, attributesToGet, new UserFilter());

        client.getUsers(userFilter, options, (user) -> resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues)));
    }

    private void getUserByUid(String userId, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        UserFilter filter = applyFieldsFilter(configuration, attributesToGet, new UserFilter());
        User user = client.getUserByUid(userId, filter);

        resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
    }

    private void getUserByNameAttr(String attrValue, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        attrValue = attrValue.replace("\"", "\\\"");
        UserFilter filter = new UserFilter()
                .withPage(0, 2)
                .withQuery(configuration.getUsernameAttribute() + ":\"" + attrValue + "\"");
        filter = applyFieldsFilter(configuration, attributesToGet, filter);

        List<User> response = client.getUserByNameAttr(attrValue, filter);

        for (User user : response) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }
    }

    private void getUserByEmail(String email, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        FieldsFilter filter = applyFieldsFilter(configuration, attributesToGet, new FieldsFilter());
        List<User> response = client.getUserByEmail(email, filter);

        for (User user : response) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }
    }

    private ConnectorObject toConnectorObject(User user, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_OBJECT_CLASS)
                // Always returns "user_id"
                .setUid(user.getId());

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(!user.isBlocked()));
        }
        if (shouldReturn(attributesToGet, ATTR_CREATED_AT)) {
            builder.addAttribute(ATTR_CREATED_AT, Auth0Utils.toZoneDateTime(user.getCreatedAt()));
        }
        if (shouldReturn(attributesToGet, ATTR_UPDATED_AT)) {
            builder.addAttribute(ATTR_UPDATED_AT, Auth0Utils.toZoneDateTime(user.getUpdatedAt()));
        }
        if (shouldReturn(attributesToGet, ATTR_LAST_IP)) {
            builder.addAttribute(ATTR_LAST_IP, user.getLastIP());
        }
        if (shouldReturn(attributesToGet, ATTR_LAST_LOGIN)) {
            builder.addAttribute(ATTR_LAST_LOGIN, Auth0Utils.toZoneDateTime(user.getLastLogin()));
        }
        if (shouldReturn(attributesToGet, ATTR_LOGINS_COUNT)) {
            builder.addAttribute(ATTR_LOGINS_COUNT, user.getLoginsCount());
        }

        // __NAME__
        if (isNameAttribute(configuration, ATTR_EMAIL)) {
            builder.setName(user.getEmail());
        } else if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
            builder.setName(user.getPhoneNumber());
        } else if (isNameAttribute(configuration, ATTR_USERNAME)) {
            builder.setName(user.getUsername());
        } else {
            builder.setName(user.getId());
        }

        // Standard
        ALLOWED_NAME_ATTRS.stream()
                .filter(attr -> !attr.equals(configuration.getUsernameAttribute()) && !attr.equals(ATTR_USER_ID))
                .forEach(attr -> {
                    if (shouldReturn(attributesToGet, attr)) {
                        if (attr.equals(ATTR_EMAIL)) {
                            builder.addAttribute(attr, user.getEmail());
                        }
                        if (attr.equals(ATTR_PHONE_NUMBER)) {
                            builder.addAttribute(attr, user.getPhoneNumber());
                        }
                        if (attr.equals(ATTR_USERNAME)) {
                            builder.addAttribute(attr, user.getUsername());
                        }
                    }
                });
        if (shouldReturn(attributesToGet, ATTR_EMAIL_VERIFIED)) {
            builder.addAttribute(ATTR_EMAIL_VERIFIED, user.isEmailVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_PHONE_VERIFIED)) {
            builder.addAttribute(ATTR_PHONE_VERIFIED, user.isPhoneVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_PICTURE)) {
            builder.addAttribute(ATTR_PICTURE, user.getPicture());
        }
        if (shouldReturn(attributesToGet, ATTR_NAME)) {
            builder.addAttribute(ATTR_NAME, user.getName());
        }
        if (shouldReturn(attributesToGet, ATTR_NICKNAME)) {
            builder.addAttribute(ATTR_NICKNAME, user.getNickname());
        }
        if (shouldReturn(attributesToGet, ATTR_GIVEN_NAME)) {
            builder.addAttribute(ATTR_GIVEN_NAME, user.getGivenName());
        }
        if (shouldReturn(attributesToGet, ATTR_FAMILY_NAME)) {
            builder.addAttribute(ATTR_FAMILY_NAME, user.getFamilyName());
        }
        if (shouldReturn(attributesToGet, ATTR_CONNECTION)) {
            builder.addAttribute(ATTR_CONNECTION, user.getIdentities().stream().map(i -> i.getConnection()).collect(Collectors.toList()));
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching association
            LOGGER.ok("Suppress fetching association because return partial attribute values is requested");

            if (shouldReturn(attributesToGet, ATTR_ROLES)) {
                builder.addAttribute(createIncompleteAttribute(ATTR_ROLES));
            }
            if (shouldReturn(attributesToGet, ATTR_ORGANIZATIONS)) {
                builder.addAttribute(createIncompleteAttribute(ATTR_ORGANIZATIONS));
            }
            if (shouldReturn(attributesToGet, ATTR_ORGANIZATION_ROLES)) {
                builder.addAttribute(createIncompleteAttribute(ATTR_ORGANIZATION_ROLES));
            }
            if (shouldReturn(attributesToGet, ATTR_PERMISSIONS)) {
                builder.addAttribute(createIncompleteAttribute(ATTR_PERMISSIONS));
            }
        } else {
            if (attributesToGet == null) {
                // Suppress fetching association default
                LOGGER.ok("Suppress fetching roles because returned by default is true");

            } else {
                if (shouldReturn(attributesToGet, ATTR_ROLES)) {
                    // Fetch roles
                    LOGGER.ok("Fetching roles because attributes to get is requested");

                    List<Role> roles = associationHandler.getRolesForUser(user.getId());
                    builder.addAttribute(ATTR_ROLES,
                            roles.stream().map(r -> r.getId()).collect(Collectors.toList()));
                }
                if (shouldReturn(attributesToGet, ATTR_ORGANIZATIONS)) {
                    // Fetch organizations
                    LOGGER.ok("Fetching organizations because attributes to get is requested");

                    List<Organization> orgs = associationHandler.getOrganizationsForUser(user.getId());
                    builder.addAttribute(ATTR_ORGANIZATIONS,
                            orgs.stream().map(o -> o.getId()).collect(Collectors.toList()));
                }
                if (shouldReturn(attributesToGet, ATTR_ORGANIZATION_ROLES)) {
                    // Fetch organization roles
                    LOGGER.ok("Fetching organization roles because attributes to get is requested");

                    Map<String, List<String>> orgRoles = associationHandler.getOrganizationRolesForUser(user.getId());
                    builder.addAttribute(ATTR_ORGANIZATION_ROLES, toTextOrgRoles(orgRoles));
                }
                if (shouldReturn(attributesToGet, ATTR_PERMISSIONS)) {
                    // Fetch permissions
                    LOGGER.ok("Fetching permissions because attributes to get is requested");

                    List<Permission> permissions = associationHandler.getPermissionsForUser(user.getId());
                    builder.addAttribute(ATTR_PERMISSIONS, toTextPermissions(permissions));
                }
            }
        }

        return builder.build();
    }

    private static <T extends FieldsFilter> T applyFieldsFilter(Auth0Configuration configuration, Set<String> attributesToGet, T filter) {
        if (!attributesToGet.isEmpty()) {
            for (String attr : attributesToGet) {
                if (ALLOWED_FIELDS_SET.contains(attr)) {
                    filter.withFields(attr, true);
                } else {
                    if (attr.equals(Name.NAME)) {
                        if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
                            filter.withFields(ATTR_PHONE_NUMBER, true);
                        } else {
                            filter.withFields(ATTR_EMAIL, true);
                        }
                        continue;
                    } else if (attr.equals(ENABLE_NAME)) {
                        filter.withFields(ATTR_BLOCKED, true);
                    }
                    filter = null;
                    break;
                }
            }
        }
        return filter;
    }
}
