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
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Permission;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.organizations.Organization;
import com.auth0.json.mgmt.users.User;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.auth0.Auth0Utils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.PASSWORD_NAME;

public class Auth0UserHandler {

    public static final String USER_OBJECT_CLASS_PREFIX = "User_";

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    private static final String SMS_CONNECTION = "sms";

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

    private static final String ATTR_USER_METADATA = "user_metadata";
    private static final String ATTR_APP_METADATA = "app_metadata";

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
            // Not supported for Get User API
            // ATTR_PHONE_VERIFIED,
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
    private static final Set<String> ADDITIONAL_ALLOWED_FIELDS_SET = Stream.of(
            ATTR_PHONE_VERIFIED
    ).collect(Collectors.toSet());

    private final Auth0Configuration configuration;
    private final Auth0Client client;
    private final Auth0AssociationHandler associationHandler;
    private final Map<String, AttributeInfo> schema;
    private final String connection;
    private final ObjectClass objectClass;

    public Auth0UserHandler(Auth0Configuration configuration, Auth0Client client,
                            Map<String, AttributeInfo> schema, String connection) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.connection = connection;
        this.objectClass = new ObjectClass(USER_OBJECT_CLASS_PREFIX + connection);
        this.associationHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getSchema(Auth0Configuration config, String databaseConnection) {
        LOGGER.ok("User: {0}", databaseConnection);

        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS_PREFIX + databaseConnection);

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
        if (databaseConnection.equals(SMS_CONNECTION)) {
            usernameBuilder.setNativeName(ATTR_PHONE_NUMBER);
            builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_EMAIL).build());
        } else {
            usernameBuilder.setNativeName(ATTR_EMAIL);
            builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PHONE_NUMBER).build());
        }
        builder.addAttributeInfo(usernameBuilder.build());

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

        // Custom user/app metadata
        toAttributeInfoList(config.getUserMetadataSchema(), ATTR_USER_METADATA)
                .forEach(a -> builder.addAttributeInfo(a));
        toAttributeInfoList(config.getAppMetadataSchema(), ATTR_APP_METADATA)
                .forEach(a -> builder.addAttributeInfo(a));

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
        // Read-only because the connection is resolved by objectClass
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CONNECTION)
                .setCreateable(false)
                .setUpdateable(false)
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

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/post_users
     *
     * @param attributes
     * @return
     * @throws Auth0Exception
     */
    public Uid createUser(Set<Attribute> attributes) throws Auth0Exception {
        User newUser = new User();
        newUser.setConnection(connection);

        List<Object> roles = null;
        List<Object> orgs = null;
        List<Object> orgRoles = null;
        List<Object> permissions = null;
        MetadataCreator userMetadata = new MetadataCreator(schema);
        MetadataCreator appMetadata = new MetadataCreator(schema);

        for (Attribute attr : attributes) {
            // __NAME__
            if (attr.getName().equals(Name.NAME)) {
                if (isSMS()) {
                    newUser.setPhoneNumber(AttributeUtil.getAsStringValue(attr));
                } else {
                    newUser.setEmail(AttributeUtil.getAsStringValue(attr));
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

            // user/app metadata
            else if (attr.getName().startsWith(ATTR_USER_METADATA)) {
                userMetadata.apply(attr, ATTR_USER_METADATA);

            } else if (attr.getName().startsWith(ATTR_APP_METADATA)) {
                appMetadata.apply(attr, ATTR_APP_METADATA);
            }

            // Metadata
            else if (attr.getName().equals(OperationalAttributes.ENABLE_NAME)) {
                newUser.setBlocked(!AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeUtil.getGuardedStringValue(attr).access(c -> {
                    newUser.setPassword(c.clone());
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

        if (!userMetadata.willCreate()) {
            newUser.setUserMetadata(userMetadata.getMetadata());
        }
        if (!appMetadata.willCreate()) {
            newUser.setAppMetadata(appMetadata.getMetadata());
        }

        User response = client.createUser(newUser);

        Uid newUid = new Uid(response.getId(), new Name(isSMS() ? response.getPhoneNumber() : response.getEmail()));

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

    private static class MetadataCreator {
        private final Map<String, AttributeInfo> schema;
        private Map<String, Object> metadata = null;

        public MetadataCreator(Map<String, AttributeInfo> schema) {
            this.schema = schema;
        }

        public void apply(Attribute attr, String prefix) {
            AttributeInfo info = schema.get(attr.getName());
            if (info == null || !info.getName().startsWith(prefix)) {
                throw new InvalidAttributeValueException("Unknown metadata: " + attr.getName());
            }

            metadata = initIfNecessary(metadata, Object.class);

            String fieldName = attr.getName().substring(prefix.length() + 1);
            if (info.isMultiValued()) {
                // The type of the value is string or long
                metadata.put(fieldName, attr.getValue());
            } else {
                if (info.getType().isAssignableFrom(Long.class)) {
                    metadata.put(fieldName, AttributeUtil.getLongValue(attr));
                } else {
                    metadata.put(fieldName, AttributeUtil.getAsStringValue(attr));
                }
            }
        }

        public boolean willCreate() {
            return metadata != null && !metadata.isEmpty();
        }

        public Map<String, Object> getMetadata() {
            return metadata;
        }

        private <T> Map<String, T> initIfNecessary(Map<String, T> map, Class<T> clazz) {
            if (map == null) {
                return new HashMap<String, T>();
            }
            return map;
        }
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/patch_users_by_id
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     * @throws Auth0Exception
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws Auth0Exception {
        User modifyUser = new User();
        // If we are updating email, email_verified, phone_number, phone_verified,
        // username or password of a secondary identity, we need to specify the connection property too.
        modifyUser.setConnection(connection);

        List<Object> rolesToAdd = null;
        List<Object> rolesToRemove = null;
        List<Object> orgsToAdd = null;
        List<Object> orgsToRemove = null;
        List<Object> orgRolesToAdd = null;
        List<Object> orgRolesToRemove = null;
        List<Object> permissionsToAdd = null;
        List<Object> permissionsToRemove = null;
        MetadataUpdater userMetadata = new MetadataUpdater(schema);
        MetadataUpdater appMetadata = new MetadataUpdater(schema);

        boolean doUpdateUser = false;

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Uid.NAME)) {
                // Doesn't support to modify 'user_id'
                throwInvalidSchema(delta.getName());
            }

            // __NAME__
            else if (delta.getName().equals(Name.NAME)) {
                if (isSMS()) {
                    modifyUser.setPhoneNumber(AttributeDeltaUtil.getAsStringValue(delta));
                } else {
                    modifyUser.setEmail(AttributeDeltaUtil.getAsStringValue(delta));
                }
                doUpdateUser = true;
            }

            // Standard Attributes
            else if (delta.getName().equals(ATTR_EMAIL)) {
                modifyUser.setEmail(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_NICKNAME)) {
                modifyUser.setNickname(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_PHONE_NUMBER)) {
                modifyUser.setPhoneNumber(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_GIVEN_NAME)) {
                modifyUser.setGivenName(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_FAMILY_NAME)) {
                modifyUser.setFamilyName(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_NAME)) {
                modifyUser.setName(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_PICTURE)) {
                modifyUser.setPicture(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_USERNAME)) {
                modifyUser.setUsername(AttributeDeltaUtil.getAsStringValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_EMAIL_VERIFIED)) {
                modifyUser.setEmailVerified(AttributeDeltaUtil.getBooleanValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_VERIFY_EMAIL)) {
                modifyUser.setVerifyEmail(AttributeDeltaUtil.getBooleanValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_PHONE_VERIFIED)) {
                modifyUser.setPhoneVerified(AttributeDeltaUtil.getBooleanValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(ATTR_VERIFY_PHONE_NUMBER)) {
                modifyUser.setVerifyPhoneNumber(AttributeDeltaUtil.getBooleanValue(delta));
                doUpdateUser = true;
            }

            // user/app metadata
            else if (delta.getName().startsWith(ATTR_USER_METADATA)) {
                userMetadata.apply(delta, ATTR_USER_METADATA);
                doUpdateUser = true;

            } else if (delta.getName().startsWith(ATTR_APP_METADATA)) {
                appMetadata.apply(delta, ATTR_APP_METADATA);
                doUpdateUser = true;
            }

            // Metadata
            else if (delta.getName().equals(OperationalAttributes.ENABLE_NAME)) {
                modifyUser.setBlocked(!AttributeDeltaUtil.getBooleanValue(delta));
                doUpdateUser = true;

            } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeDeltaUtil.getGuardedStringValue(delta).access(c -> {
                    modifyUser.setPassword(c.clone());
                });
                doUpdateUser = true;
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

        if (doUpdateUser) {
            // If the delta contains changes of multivalued field in user/app metadata,
            // we need to fetch the current metadata before updating it to merge the values.
            Map<String, Object> currentUserMetadata = null;
            Map<String, Object> currentAppMetadata = null;
            if (userMetadata.hasMultivaluedChange() || appMetadata.hasMultivaluedChange()) {
                UserFilter filter = new UserFilter();
                if (userMetadata.hasMultivaluedChange()) {
                    filter.withFields(ATTR_USER_METADATA, true);
                }
                if (appMetadata.hasMultivaluedChange()) {
                    filter.withFields(ATTR_APP_METADATA, true);
                }
                User current = client.getUserByUid(uid.getUidValue(), filter);
                currentUserMetadata = current.getUserMetadata();
                currentAppMetadata = current.getAppMetadata();
            }
            if (userMetadata.willUpdate()) {
                modifyUser.setUserMetadata(userMetadata.getMetadata(currentUserMetadata));
            }
            if (appMetadata.willUpdate()) {
                modifyUser.setAppMetadata(appMetadata.getMetadata(currentAppMetadata));
            }

            client.updateUser(uid, modifyUser);
        }

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

    private static class MetadataUpdater {
        private final Map<String, AttributeInfo> schema;

        // For update
        Map<String, Object> metadataToReplace = null;
        Map<String, List> metadataToAdd = null;
        Map<String, List> metadataToRemove = null;

        public MetadataUpdater(Map<String, AttributeInfo> schema) {
            this.schema = schema;
        }

        public void apply(AttributeDelta delta, String prefix) {
            AttributeInfo info = schema.get(delta.getName());
            if (info == null || !info.getName().startsWith(prefix)) {
                throw new InvalidAttributeValueException("Unknown metadata: " + delta.getName());
            }

            String fieldName = delta.getName().substring(prefix.length() + 1);
            if (info.isMultiValued()) {
                List<Object> valuesToAdd = delta.getValuesToAdd();
                List<Object> valuesToRemove = delta.getValuesToRemove();

                if (valuesToAdd != null) {
                    metadataToAdd = initIfNecessary(metadataToAdd, List.class);
                    metadataToAdd.put(fieldName, valuesToAdd);
                }
                if (valuesToRemove != null) {
                    metadataToRemove = initIfNecessary(metadataToRemove, List.class);
                    metadataToRemove.put(fieldName, valuesToRemove);
                }
            } else {
                metadataToReplace = initIfNecessary(metadataToReplace, Object.class);

                if (info.getType().isAssignableFrom(Long.class)) {
                    metadataToReplace.put(fieldName, AttributeDeltaUtil.getBigDecimalValue(delta));
                } else {
                    metadataToReplace.put(fieldName, AttributeDeltaUtil.getAsStringValue(delta));
                }
            }
        }

        public boolean willUpdate() {
            return hasChange(metadataToReplace, metadataToAdd, metadataToRemove);
        }

        public boolean hasMultivaluedChange() {
            return hasChange(metadataToAdd, metadataToRemove);
        }

        public Map<String, Object> getMetadata(Map<String, Object> currentMetadata) {
            Map<String, Object> result;
            if (currentMetadata == null) {
                result = new HashMap<>();
            } else {
                result = currentMetadata;
            }

            if (hasMultivaluedChange()) {
                // For multiple values, merge with current metadata
                if (hasChange(metadataToRemove)) {
                    for (Map.Entry<String, List> kv : metadataToRemove.entrySet()) {
                        Object cv = currentMetadata.get(kv.getKey());
                        if (cv != null && cv instanceof List) {
                            ((List) cv).removeAll(kv.getValue());
                        }
                    }
                }
                if (hasChange(metadataToAdd)) {
                    for (Map.Entry<String, List> kv : metadataToAdd.entrySet()) {
                        Object cv = currentMetadata.get(kv.getKey());
                        if (cv != null && cv instanceof List) {
                            ((List) cv).addAll(kv.getValue());
                        } else {
                            currentMetadata.put(kv.getKey(), kv.getValue());
                        }
                    }
                }
            }
            if (hasChange(metadataToReplace)) {
                for (Map.Entry<String, Object> kv : metadataToReplace.entrySet()) {
                    result.put(kv.getKey(), kv.getValue());
                }
            }

            return result;
        }

        private <T> Map<String, T> initIfNecessary(Map<String, T> map, Class<T> clazz) {
            if (map == null) {
                return new HashMap<String, T>();
            }
            return map;
        }

        private boolean hasChange(Map<?, ?>... map) {
            if (map == null) {
                return true;
            }
            return Arrays.stream(map).anyMatch(m -> m != null && !m.isEmpty());
        }
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Users/delete_users_by_id
     *
     * @param uid
     * @param options
     * @throws Auth0Exception
     */
    public void deleteUser(Uid uid, OperationOptions options) throws Auth0Exception {
        client.deleteUser(uid);
    }

    public int getUsers(Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) throws
            Auth0Exception {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null) {
            if (filter.isByName()) {
                // Filter by __NANE__
                if (isSMS()) {
                    return getUserByPhoneNumber(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
                } else {
                    return getUserByEmail(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
                }
            } else {
                // Filter by __UID__
                return getUserByUid(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            }
        }

        UserFilter userFilter = applyFieldsFilter(attributesToGet, new UserFilter(), ADDITIONAL_ALLOWED_FIELDS_SET)
                .withQuery("identities.connection:\"" + connection + "\"");

        return client.getUsers(userFilter, options, (user) -> resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues)));
    }

    private int getUserByUid(String userId, ResultsHandler resultsHandler, Set<String> attributesToGet,
                             boolean allowPartialAttributeValues) throws Auth0Exception {
        UserFilter filter = applyFieldsFilter(attributesToGet, new UserFilter(), Collections.emptySet());
        try {
            User user = client.getUserByUid(userId, filter);

            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        } catch (APIException e) {
            return handleSearchError(e);
        }

        return 1;
    }

    private int handleSearchError(APIException e) throws APIException {
        // We should not return any object, throw UnknownUidException when no such object
        if (e.getStatusCode() == 404) {
            return 0;
        }
        throw e;
    }

    private int getUserByPhoneNumber(String attrValue, ResultsHandler resultsHandler, Set<String> attributesToGet,
                                     boolean allowPartialAttributeValues) throws Auth0Exception {
        attrValue = attrValue.replace("\"", "\\\"");
        UserFilter filter = new UserFilter()
                .withPage(0, 1)
                .withQuery("identities.connection:\"" + connection + "\" AND phone_number:\"" + attrValue + "\"");
        filter = applyFieldsFilter(attributesToGet, filter, ADDITIONAL_ALLOWED_FIELDS_SET);

        List<User> response = client.getUsersByFilter(filter);

        for (User user : response) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }

        return response.size();
    }

    private int getUserByEmail(String email, ResultsHandler resultsHandler, Set<String> attributesToGet,
                               boolean allowPartialAttributeValues) throws Auth0Exception {
        email = email.replace("\"", "\\\"");
        UserFilter filter = new UserFilter()
                .withPage(0, 1)
                .withQuery("identities.connection:\"" + connection + "\" AND email:\"" + email + "\"");
        filter = applyFieldsFilter(attributesToGet, filter, ADDITIONAL_ALLOWED_FIELDS_SET);

        // We don't use "User's By Email" API because it can't filter by connection
        List<User> response = client.getUsersByFilter(filter);

        for (User user : response) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }

        return response.size();
    }

    private ConnectorObject toConnectorObject(User user, Set<String> attributesToGet,
                                              boolean allowPartialAttributeValues) throws Auth0Exception {
        ConnectorObjectBuilderWrapper builderWrapper = new ConnectorObjectBuilderWrapper(attributesToGet, objectClass);

        // Always returns "user_id"
        builderWrapper.applyUid(user.getId());

        // Metadata
        builderWrapper.apply(ENABLE_NAME, user.isBlocked(), Auth0Utils::buildDisable);
        builderWrapper.apply(ATTR_CREATED_AT, user.getCreatedAt(), Auth0Utils::toZoneDateTime);
        builderWrapper.apply(ATTR_UPDATED_AT, user.getUpdatedAt(), Auth0Utils::toZoneDateTime);
        builderWrapper.apply(ATTR_LAST_IP, user.getLastIP());
        builderWrapper.apply(ATTR_LAST_LOGIN, user.getLastLogin());
        builderWrapper.apply(ATTR_LOGINS_COUNT, user.getLoginsCount());

        // __NAME__
        if (isSMS()) {
            builderWrapper.applyName(user.getPhoneNumber());
            builderWrapper.apply(ATTR_EMAIL, user.getEmail());
        } else {
            builderWrapper.applyName(user.getEmail());
            builderWrapper.apply(ATTR_PHONE_NUMBER, user.getPhoneNumber());
        }

        // Standard
        builderWrapper.apply(ATTR_EMAIL_VERIFIED, user.isEmailVerified());
        builderWrapper.apply(ATTR_PHONE_VERIFIED, user.isPhoneVerified());
        builderWrapper.apply(ATTR_PICTURE, user.getPicture());
        builderWrapper.apply(ATTR_NAME, user.getName());
        builderWrapper.apply(ATTR_NICKNAME, user.getNickname());
        builderWrapper.apply(ATTR_GIVEN_NAME, user.getGivenName());
        builderWrapper.apply(ATTR_FAMILY_NAME, user.getFamilyName());
        builderWrapper.apply(ATTR_CONNECTION, user.getIdentities() != null ?
                user.getIdentities().stream().map(i -> i.getConnection()).collect(Collectors.toList()) :
                null);

        // user/app metadata
        builderWrapper.apply(user.getUserMetadata(), ATTR_USER_METADATA);
        builderWrapper.apply(user.getAppMetadata(), ATTR_APP_METADATA);

        if (allowPartialAttributeValues) {
            // Suppress fetching association
            LOGGER.ok("Suppress fetching association because return partial attribute values is requested");

            builderWrapper.apply(ATTR_ROLES, Auth0Utils::createIncompleteAttribute);
            builderWrapper.apply(ATTR_ORGANIZATIONS, Auth0Utils::createIncompleteAttribute);
            builderWrapper.apply(ATTR_ORGANIZATION_ROLES, Auth0Utils::createIncompleteAttribute);
            builderWrapper.apply(ATTR_PERMISSIONS, Auth0Utils::createIncompleteAttribute);
        } else {
            if (attributesToGet == null) {
                // Suppress fetching association default
                LOGGER.ok("Suppress fetching roles because returned by default is true");

            } else {
                if (shouldReturn(attributesToGet, ATTR_ROLES)) {
                    // Fetch roles
                    LOGGER.ok("Fetching roles because attributes to get is requested");

                    List<Role> roles = associationHandler.getRolesForUser(user.getId());
                    builderWrapper.addAttribute(ATTR_ROLES,
                            roles.stream().map(r -> r.getId()).collect(Collectors.toList()));
                }
                if (shouldReturn(attributesToGet, ATTR_ORGANIZATIONS)) {
                    // Fetch organizations
                    LOGGER.ok("Fetching organizations because attributes to get is requested");

                    List<Organization> orgs = associationHandler.getOrganizationsForUser(user.getId());
                    builderWrapper.addAttribute(ATTR_ORGANIZATIONS,
                            orgs.stream().map(o -> o.getId()).collect(Collectors.toList()));
                }
                if (shouldReturn(attributesToGet, ATTR_ORGANIZATION_ROLES)) {
                    // Fetch organization roles
                    LOGGER.ok("Fetching organization roles because attributes to get is requested");

                    Map<String, List<String>> orgRoles = associationHandler.getOrganizationRolesForUser(user.getId());
                    builderWrapper.addAttribute(ATTR_ORGANIZATION_ROLES, toTextOrgRoles(orgRoles));
                }
                if (shouldReturn(attributesToGet, ATTR_PERMISSIONS)) {
                    // Fetch permissions
                    LOGGER.ok("Fetching permissions because attributes to get is requested");

                    List<Permission> permissions = associationHandler.getPermissionsForUser(user.getId());
                    builderWrapper.addAttribute(ATTR_PERMISSIONS, toTextPermissions(permissions));
                }
            }
        }

        return builderWrapper.build();
    }

    private <T extends FieldsFilter> T applyFieldsFilter(Set<String> attributesToGet, T filter, Set<String> additionalAllowedFields) {
        if (attributesToGet != null && !attributesToGet.isEmpty()) {
            StringBuilder sb = new StringBuilder();

            for (String attr : attributesToGet) {
                if (ALLOWED_FIELDS_SET.contains(attr)) {
                    sb.append(attr);
                    sb.append(",");
                } else if (additionalAllowedFields.contains(attr)) {
                    sb.append(attr);
                    sb.append(",");
                } else {
                    if (attr.equals(Uid.NAME)) {
                        sb.append(ATTR_USER_ID);
                        sb.append(",");
                    } else if (attr.equals(Name.NAME)) {
                        if (isSMS()) {
                            sb.append(ATTR_PHONE_NUMBER);
                            sb.append(",");
                        } else {
                            sb.append(ATTR_EMAIL);
                            sb.append(",");
                        }
                    } else if (attr.equals(ENABLE_NAME)) {
                        sb.append(ATTR_BLOCKED);
                        sb.append(",");
                    } else if (attr.equals(PASSWORD_NAME)) {
                        // Ignore
                    } else if (attr.equals(ATTR_CONNECTION)) {
                        sb.append("identities.");
                        sb.append(ATTR_CONNECTION);
                        sb.append(",");
                    } else {
                        // Try to fetch with not allowed fields
                        // We need to fetch all fields
                        sb = null;
                        break;
                    }
                }
            }

            if (sb != null) {
                sb.deleteCharAt(sb.length() - 1);
                filter.withFields(sb.toString(), true);
            }
        }
        return filter;
    }

    private boolean isSMS() {
        return connection.equals(SMS_CONNECTION);
    }
}
