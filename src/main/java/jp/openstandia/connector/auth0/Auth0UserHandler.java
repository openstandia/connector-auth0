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

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersIterable;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static jp.openstandia.connector.auth0.Auth0Utils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

public class Auth0UserHandler {

    public static final ObjectClass USER_OBJECT_CLASS = new ObjectClass("User");

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    // The username for the user. Must be unique within the user pool.
    // Must be a UTF-8 string between 1 and 128 characters. After the user is created, the username cannot be changed.
    // https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
    private static final String ATTR_USERNAME = "username";

    // Also, Unique and unchangeable within the user pool
    private static final String ATTR_SUB = "sub";

    // Standard Attributes
    // https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
    private static final String ATTR_EMAIL = "email";
    private static final String ATTR_PREFERRED_USERNAME = "preferred_username";

    // Metadata
    private static final String ATTR_USER_CREATE_DATE = "UserCreateDate";
    private static final String ATTR_USER_LAST_MODIFIED_DATE = "UserLastModifiedDate";
    private static final String ATTR_USER_STATUS = "UserStatus";

    // Association
    private static final String ATTR_GROUPS = "groups";

    // Password
    private static final String ATTR_PASSWORD = "__PASSWORD__";
    private static final String ATTR_PASSWORD_PERMANENT = "password_permanent";

    // Enable
    private static final String ATTR_ENABLE = "__ENABLE__";

    private static final Auth0Filter.SubFilter SUB_FILTER = new Auth0Filter.SubFilter();

    private static final Set<String> NOT_USER_ATTRIBUTES = createNotUserAttributes();

    private static Set<String> createNotUserAttributes() {
        Set<String> attrs = new HashSet<>();
        attrs.add(Uid.NAME);
        attrs.add(Name.NAME);
        attrs.add(ATTR_USER_CREATE_DATE);
        attrs.add(ATTR_USER_LAST_MODIFIED_DATE);
        attrs.add(ATTR_USER_STATUS);
        attrs.add(ATTR_GROUPS);
        attrs.add(ATTR_PASSWORD_PERMANENT);
        attrs.addAll(OperationalAttributes.OPERATIONAL_ATTRIBUTE_NAMES);

        return Collections.unmodifiableSet(attrs);
    }

    private final Auth0Configuration configuration;
    private final CognitoIdentityProviderClient client;
    private final Auth0AssociationHandler userGroupHandler;
    private final Map<String, AttributeInfo> schema;

    public Auth0UserHandler(Auth0Configuration configuration, CognitoIdentityProviderClient client,
                            Map<String, AttributeInfo> schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.userGroupHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getUserSchema(UserPoolType userPoolType) {
        LOGGER.ok("UserPoolType: {0}", userPoolType);

        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS.getObjectClassValue());

        // sub (__UID__)
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false) // Must be optional. It is not present for create operations
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_SUB)
                        .build()
        );

        // username (__NAME__)
        // Caution!! It is prohibited to update this value which is Amazon Cognito limitation.
        AttributeInfoBuilder usernameBuilder = AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(false)
                .setNativeName(ATTR_USERNAME);
        Boolean caseSensitive;
        if (userPoolType.usernameConfiguration() != null) {
            caseSensitive = userPoolType.usernameConfiguration().caseSensitive();
            if (!caseSensitive) {
                usernameBuilder.setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE);
            }
        } else {
            caseSensitive = true;
        }
        builder.addAttributeInfo(usernameBuilder.build());

        // __ENABLE__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        // __PASSWORD__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PASSWORD_PERMANENT)
                .setType(Boolean.class)
                .setReadable(false)
                .setReturnedByDefault(false)
                .build());

        // Other attributes
        List<AttributeInfo> attrInfoList = userPoolType.schemaAttributes().stream()
                .filter(a -> !a.name().equals(ATTR_SUB))
                .map(s -> {
                    AttributeInfoBuilder attrInfo = AttributeInfoBuilder.define(s.name())
                            .setRequired(s.required())
                            .setUpdateable(s.mutable());

                    // https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SchemaAttributeType.html#CognitoUserPools-Type-SchemaAttributeType-AttributeDataType
                    switch (s.attributeDataType()) {
                        case STRING:
                            attrInfo.setType(String.class);
                            break;
                        case NUMBER:
                            attrInfo.setType(Integer.class);
                            break;
                        case DATE_TIME:
                            attrInfo.setType(ZonedDateTime.class);
                            break;
                        case BOOLEAN:
                            attrInfo.setType(Boolean.class);
                            break;
                        default:
                            attrInfo.setType(String.class);
                    }

                    if (s.name().equals(ATTR_EMAIL) || s.name().equals(ATTR_PREFERRED_USERNAME)) {
                        if (!caseSensitive) {
                            attrInfo.setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE);
                        }
                    }
                    return attrInfo.build();
                })
                .collect(Collectors.toList());

        // Metadata
        attrInfoList.add(AttributeInfoBuilder.define(ATTR_USER_CREATE_DATE)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
        attrInfoList.add(AttributeInfoBuilder.define(ATTR_USER_LAST_MODIFIED_DATE)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
        attrInfoList.add(AttributeInfoBuilder.define(ATTR_USER_STATUS)
                .setCreateable(false)
                .setUpdateable(false)
                .build());

        // Association
        attrInfoList.add(AttributeInfoBuilder.define(ATTR_GROUPS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        builder.addAllAttributeInfo(attrInfoList);

        ObjectClassInfo userSchemaInfo = builder.build();

        LOGGER.ok("The constructed User core schema: {0}", userSchemaInfo);

        return userSchemaInfo;
    }

    /**
     * The spec for AdminCreateUser:
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
     *
     * @param attributes
     * @return
     */
    public Uid createUser(Set<Attribute> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            throw new InvalidAttributeValueException("attributes not provided or empty");
        }

        UserModel newUser = new UserModel();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newUser.applyUsername(attr);

            } else if (attr.getName().equals(ENABLE_NAME)) {
                newUser.applyUserEnabled(attr);

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                newUser.applyNewPassword(attr);

            } else if (attr.getName().equals(ATTR_PASSWORD_PERMANENT)) {
                newUser.applyPasswordPermanent(attr);

            } else if (attr.getName().equals(ATTR_GROUPS)) {
                newUser.applyGroups(attr);

            } else {
                if (!schema.containsKey(attr.getName())) {
                    throw new InvalidAttributeValueException(String.format("Cognito doesn't support to set '%s' attribute of User",
                            attr.getName()));
                }
                newUser.applyUserAttribute(attr);
            }
        }

        // Generate username if IDM doesn't have mapping to username
        if (newUser.username == null) {
            newUser.username = UUID.randomUUID().toString();
        }

        AdminCreateUserRequest.Builder requestBuilder = AdminCreateUserRequest.builder()
                .userPoolId(configuration.getUserPoolID())
                .username(newUser.username)
                .userAttributes(newUser.userAttributes);

        if (configuration.isSuppressInvitationMessageEnabled()) {
            requestBuilder.messageAction(MessageActionType.SUPPRESS);
        }

        AdminCreateUserRequest request = requestBuilder.build();

        AdminCreateUserResponse result = client.adminCreateUser(request);

        checkCognitoResult(result, "AdminCreateUser");

        UserType user = result.user();
        Uid newUid = new Uid(user.attributes().stream()
                .filter(a -> a.name().equals(ATTR_SUB))
                .findFirst()
                .get()
                .value(),
                new Name(user.username()));

        // We need to call another API to enable/disable user, password changing and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Cognito data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        if (Boolean.FALSE.equals(newUser.userEnabled)) {
            disableUser(newUid, newUid.getNameHint());
        }
        updatePassword(user.username(), newUser.newPassword, newUser.passwordPermanent);
        userGroupHandler.addGroupsToUser(newUid.getNameHint(), newUser.addGroups);

        return newUid;
    }

    private void updatePassword(String username, GuardedString password, final Boolean permanent) {
        if (password == null) {
            return;
        }
        password.access(a -> {
            String clearPassword = String.valueOf(a);

            AdminSetUserPasswordRequest request = AdminSetUserPasswordRequest.builder()
                    .userPoolId(configuration.getUserPoolID())
                    .username(username)
                    .permanent(permanent)
                    .password(clearPassword)
                    .build();

            try {
                AdminSetUserPasswordResponse response = client.adminSetUserPassword(request);

                checkCognitoResult(response, "AdminSetUserPassword");
            } catch (InvalidPasswordException e) {
                InvalidAttributeValueException ex = new InvalidAttributeValueException("Password policy error in cognito", e);
                ex.setAffectedAttributeNames(Arrays.asList(OperationalAttributes.PASSWORD_NAME));
                throw ex;
            }
        });
    }

    /**
     * The spec for AdminUpdateUserAttributes:
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        Name name = resolveName(uid, options);

        UserModel modifyUser = new UserModel();

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Uid.NAME) || delta.getName().equals(Name.NAME)) {
                // Cognito doesn't support to modify 'username' and 'sub'
                invalidSchema(delta.getName());

            } else if (delta.getName().equals(ENABLE_NAME)) {
                modifyUser.applyUserEnabled(delta);

            } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                modifyUser.applyNewPassword(delta);

            } else if (delta.getName().equals(ATTR_PASSWORD_PERMANENT)) {
                modifyUser.applyPasswordPermanent(delta);

            } else if (delta.getName().equals(ATTR_GROUPS)) {
                modifyUser.applyGroups(delta);

            } else if (schema.containsKey(delta.getName())) {
                modifyUser.applyUserAttribute(delta);

            } else {
                invalidSchema(delta.getName());
            }
        }

        if (!modifyUser.userAttributes.isEmpty()) {
            AdminUpdateUserAttributesRequest request = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(configuration.getUserPoolID())
                    .username(name.getNameValue())
                    .userAttributes(modifyUser.userAttributes)
                    .build();
            try {
                AdminUpdateUserAttributesResponse result = client.adminUpdateUserAttributes(request);

                checkCognitoResult(result, "AdminUpdateUserAttributes");
            } catch (UserNotFoundException e) {
                LOGGER.warn("Not found user when deleting. uid: {0}", uid);
                throw new UnknownUidException(uid, USER_OBJECT_CLASS);
            }
        }

        // We need to call another API to enable/disable user, password changing and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Cognito data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        enableOrDisableUser(uid, name, modifyUser.userEnabled);
        updatePassword(name.getNameValue(), modifyUser.newPassword, modifyUser.passwordPermanent);
        userGroupHandler.updateGroupsToUser(name, modifyUser.addGroups, modifyUser.removeGroups);

        return null;
    }

    private class UserModel {
        String username = null;
        Boolean userEnabled = null;
        GuardedString newPassword = null;
        Boolean passwordPermanent = null;
        List<AttributeType> userAttributes = new ArrayList<>();
        List<Object> addGroups = new ArrayList<>();
        List<Object> removeGroups = new ArrayList<>();

        public void applyUsername(Attribute attr) {
            this.username = AttributeUtil.getAsStringValue(attr);
        }

        void applyUserEnabled(Attribute attr) {
            this.userEnabled = AttributeUtil.getBooleanValue(attr);
        }

        void applyUserEnabled(AttributeDelta delta) {
            this.userEnabled = AttributeDeltaUtil.getBooleanValue(delta);
        }

        void applyNewPassword(Attribute attr) {
            this.newPassword = AttributeUtil.getGuardedStringValue(attr);
        }

        void applyNewPassword(AttributeDelta delta) {
            this.newPassword = AttributeDeltaUtil.getGuardedStringValue(delta);
        }

        void applyPasswordPermanent(Attribute attr) {
            this.passwordPermanent = AttributeUtil.getBooleanValue(attr);
        }

        void applyPasswordPermanent(AttributeDelta delta) {
            this.passwordPermanent = AttributeDeltaUtil.getBooleanValue(delta);
        }

        void applyUserAttribute(Attribute attr) {
            this.userAttributes.add(toCognitoAttribute(schema, attr));
        }

        void applyUserAttribute(AttributeDelta delta) {
            // When the IDM decided to delete the attribute, the value is empty
            if (delta.getValuesToReplace().isEmpty()) {
                this.userAttributes.add(toCognitoAttributeForDelete(delta));
            } else {
                this.userAttributes.add(toCognitoAttribute(schema, delta));
            }
        }

        void applyGroups(Attribute attr) {
            this.addGroups.addAll(attr.getValue());
        }

        void applyGroups(AttributeDelta delta) {
            if (delta.getValuesToAdd() != null) {
                this.addGroups.addAll(delta.getValuesToAdd());
            }
            if (delta.getValuesToRemove() != null) {
                this.removeGroups.addAll(delta.getValuesToRemove());
            }
        }
    }

    private void enableOrDisableUser(Uid uid, Name name, Boolean userEnabled) {
        if (userEnabled != null) {
            if (userEnabled) {
                enableUser(uid, name);
            } else {
                disableUser(uid, name);
            }
        }
    }

    private void enableUser(Uid uid, Name name) {
        AdminEnableUserRequest.Builder request = AdminEnableUserRequest.builder()
                .userPoolId(configuration.getUserPoolID())
                .username(name.getNameValue());
        try {
            AdminEnableUserResponse result = client.adminEnableUser(request.build());

            checkCognitoResult(result, "AdminEnableUser");
        } catch (UserNotFoundException e) {
            LOGGER.warn("Not found user when enabling. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
    }

    private void disableUser(Uid uid, Name name) {
        AdminDisableUserRequest.Builder request = AdminDisableUserRequest.builder()
                .userPoolId(configuration.getUserPoolID())
                .username(name.getNameValue());
        try {
            AdminDisableUserResponse result = client.adminDisableUser(request.build());

            checkCognitoResult(result, "AdminDisableUser");
        } catch (UserNotFoundException e) {
            LOGGER.warn("Not found user when disabling. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
    }

    /**
     * The spec for AdminDeleteUser:
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUser.html
     *
     * @param uid
     * @param options
     */
    public void deleteUser(Uid uid, OperationOptions options) {
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }

        Name name = resolveName(uid, options);

        try {
            AdminDeleteUserResponse result = client.adminDeleteUser(AdminDeleteUserRequest.builder()
                    .userPoolId(configuration.getUserPoolID())
                    .username(name.getNameValue()).build());

            checkCognitoResult(result, "AdminDeleteUser");
        } catch (UserNotFoundException e) {
            LOGGER.warn("Not found user when deleting. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
    }

    private Name resolveName(Uid uid, OperationOptions options) {
        Name nameHint = uid.getNameHint();
        if (nameHint != null) {
            return nameHint;
        }

        // Fallback
        // If uid doesn't have Name hint, find the user by uid(sub)
        UserType user = findUserByUid(uid.getUidValue());
        if (user == null) {
            LOGGER.warn("Not found user when updating or deleting. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
        return new Name(user.username());
    }

    private UserType findUserByUid(String uid) {
        ListUsersResponse result = client.listUsers(ListUsersRequest.builder()
                .userPoolId(configuration.getUserPoolID())
                .filter(SUB_FILTER.toFilterString(uid)).build());

        checkCognitoResult(result, "ListUsers");

        // ListUsers returns empty users list if no hits
        List<UserType> users = result.users();
        if (users.isEmpty()) {
            return null;
        }

        if (users.size() > 1) {
            throw new ConnectorException(String.format("Unexpected error. ListUsers returns multiple users when searching by sub = \"%s\"", uid));
        }

        return result.users().get(0);
    }

    private AdminGetUserResponse findUserByName(String username) {
        AdminGetUserResponse result = client.adminGetUser(AdminGetUserRequest.builder()
                .userPoolId(configuration.getUserPoolID())
                .username(username).build());

        checkCognitoResult(result, "AdminGetUser");

        return result;
    }

    public void getUsers(Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null && filter.isByName()) {
            getUserByName(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            return;
        }

        ListUsersRequest.Builder request = ListUsersRequest.builder();
        request.userPoolId(configuration.getUserPoolID());
        if (filter != null) {
            request.filter(filter.toFilterString(schema));
        }

        // Caution: we can't use 'request.attributesToGet(attributesToGet)' to filter the user's attributes
        // because of Cognito limitation.
        // See https://github.com/openstandia/connector-amazon-cognito-user-pool/issues/2

        ListUsersIterable result = client.listUsersPaginator(request.build());

        result.forEach(r -> r.users().forEach(u -> resultsHandler.handle(toConnectorObject(u, attributesToGet, allowPartialAttributeValues))));
    }


    private void getUserByName(String username, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        AdminGetUserResponse result = findUserByName(username);
        resultsHandler.handle(toConnectorObject(result, attributesToGet, allowPartialAttributeValues));
    }

    private ConnectorObject toConnectorObject(AdminGetUserResponse result, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        return toConnectorObject(result.username(), result.enabled(), result.userCreateDate(), result.userLastModifiedDate(),
                result.userStatusAsString(), result.userAttributes(), attributesToGet, allowPartialAttributeValues);
    }

    private ConnectorObject toConnectorObject(UserType u, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        return toConnectorObject(u.username(), u.enabled(), u.userCreateDate(), u.userLastModifiedDate(),
                u.userStatusAsString(), u.attributes(), attributesToGet, allowPartialAttributeValues);
    }

    private boolean shouldReturn(Set<String> attrsToGetSet, String attr) {
        if (attrsToGetSet == null) {
            return true;
        }
        return attrsToGetSet.contains(attr);
    }

    private ConnectorObject toConnectorObject(String username, boolean enabled,
                                              Instant userCreateDate, Instant userLastModifiedDate,
                                              String status, List<AttributeType> attributes,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues) {

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_OBJECT_CLASS)
                // Always returns "username"
                .setName(username);

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(enabled));
        }
        if (shouldReturn(attributesToGet, ATTR_USER_CREATE_DATE)) {
            builder.addAttribute(ATTR_USER_CREATE_DATE, Auth0Utils.toZoneDateTime(userCreateDate));
        }
        if (shouldReturn(attributesToGet, ATTR_USER_LAST_MODIFIED_DATE)) {
            builder.addAttribute(ATTR_USER_LAST_MODIFIED_DATE, Auth0Utils.toZoneDateTime(userLastModifiedDate));
        }
        if (shouldReturn(attributesToGet, ATTR_USER_STATUS)) {
            builder.addAttribute(ATTR_USER_STATUS, status);
        }

        for (AttributeType a : attributes) {
            // Always returns "sub"
            if (a.name().equals(ATTR_SUB)) {
                builder.setUid(a.value());
            } else {
                AttributeInfo attributeInfo = schema.get(a.name());
                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttribute(attributeInfo, a));
                }
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching groups
            LOGGER.ok("Suppress fetching groups because return partial attribute values is requested");

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_GROUPS).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching groups default
                LOGGER.ok("Suppress fetching groups because returned by default is true");

            } else if (shouldReturn(attributesToGet, ATTR_GROUPS)) {
                // Fetch groups
                LOGGER.ok("Fetching groups because attributes to get is requested");

                List<String> groups = userGroupHandler.getGroupsForUser(username);
                builder.addAttribute(ATTR_GROUPS, groups);
            }
        }

        return builder.build();
    }
}
