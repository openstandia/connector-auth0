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
import com.auth0.client.mgmt.filter.FieldsFilter;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import com.auth0.net.Request;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static jp.openstandia.connector.auth0.Auth0Utils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.PASSWORD_NAME;

public class Auth0UserHandler {

    public static final ObjectClass USER_OBJECT_CLASS = new ObjectClass("User");

    private static final Log LOGGER = Log.getLog(Auth0UserHandler.class);

    // Email
    private static final String ATTR_EMAIL = "email";

    // Unique and unchangeable
    private static final String ATTR_USER_ID = "user_id";

    // Standard Attributes
    private static final String ATTR_NICKNAME = "nickname";
    private static final String ATTR_PHONE_NUMBER = "phone_number";
    private static final String ATTR_GIVEN_NAME = "given_name";
    private static final String ATTR_FAMILY_NAME = "family_name";
    // Full name e.g. "John Doe"
    private static final String ATTR_NAME = "name";
    // Picture URI e.g. "https://secure.gravatar.com/avatar/15626c5e0c749cb912f9d1ad48dba440?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png"
    private static final String ATTR_PICTURE = "picture";
    // Username e.g. "johndoe"
    // Only valid if the connection requires a username
    private static final String ATTR_USERNAME = "username";
    // Whether this email address is verified (true) or unverified (false)
    // User will receive a verification email after creation if email_verified is false or not specified
    private static final String ATTR_EMAIL_VERIFIED = "email_verified";
    // Whether the user will receive a verification email after creation (true) or no email (false)
    // Overrides behavior of email_verified parameter.
    private static final String ATTR_VERIFY_EMAIL = "verify_email";
    private static final String ATTR_PHONE_VERIFIED = "phone_verified";
    // Whether this user was blocked by an administrator (true) or not (false)
    private static final String ATTR_BLOCKED = "blocked";
    private static final String ATTR_CONNECTION = "connection";

    // Metadata
    private static final String ATTR_CREATED_AT = "created_at";
    private static final String ATTR_UPDATED_AT = "updated_at";
    private static final String ATTR_MULTIFACTOR_LAST_MODIFIED = "multifactor_last_modified";
    private static final String ATTR_LAST_IP = "last_ip";
    private static final String ATTR_LAST_LOGIN = "last_login";
    private static final String ATTR_LOGINS_COUNT = "logins_count";

    // Association
    private static final String ATTR_ROLES = "roles";
    private static final String ATTR_PERMISSION = "permissions";

    // Password
    // Initial password for this user (mandatory only for auth0 connection strategy)
    private static final String ATTR_PASSWORD = PASSWORD_NAME;

    // Enable
    private static final String ATTR_ENABLE = ENABLE_NAME;

    private static final Auth0Filter.SubFilter SUB_FILTER = new Auth0Filter.SubFilter();

    private final Auth0Configuration configuration;
    private final CognitoIdentityProviderClient client;
    private final ManagementAPI client2;
    private final Auth0AssociationHandler userRoleHandler;
    private final Map<String, AttributeInfo> schema;
    private final Auth0Connector connector;

    public Auth0UserHandler(Auth0Connector connector, Auth0Configuration configuration, ManagementAPI client,
                            Map<String, AttributeInfo> schema) {
        this.connector = connector;
        this.configuration = configuration;
        this.client = null;
        this.client2 = client;
        this.schema = schema;
        this.userRoleHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getUserSchema(Auth0Configuration config) {
        LOGGER.ok("User: {0}");

        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS.getObjectClassValue());

        // sub (__UID__)
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false)
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_USER_ID)
                        .build()
        );

        // username (__NAME__)
        // CaseSensitive
        AttributeInfoBuilder usernameBuilder = AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true) // The API doc says it's optional, but default connection requires email
                .setUpdateable(true);
        // SMS for Passwordless mode
        if (isNameAttribute(config, ATTR_PHONE_NUMBER)) {
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
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_USERNAME).build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_EMAIL_VERIFIED)
                .setType(Boolean.class)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_VERIFY_EMAIL)
                .setType(Boolean.class)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PHONE_VERIFIED)
                .setType(Boolean.class)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_BLOCKED)
                .setType(Boolean.class)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CONNECTION)
                .setMultiValued(true)
                .build());

        // Metadata
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
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_MULTIFACTOR_LAST_MODIFIED)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());
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
        if (attributes == null || attributes.isEmpty()) {
            throw new InvalidAttributeValueException("attributes not provided or empty");
        }

        User newUser = new User();
        List<Object> roles = null;

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newUser.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ENABLE_NAME)) {
                newUser.setBlocked(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeUtil.getGuardedStringValue(attr).access(c -> {
                    newUser.setPassword(c);
                });

            } else if (attr.getName().equals(ATTR_ROLES)) {
                roles = attr.getValue();

            } else {
                if (!schema.containsKey(attr.getName())) {
                    invalidSchema(attr.getName());
                }
            }
        }

        Request<User> request = client2.users().create(newUser);
        User response = request.execute();

        Uid newUid = new Uid(response.getId(), new Name(response.getEmail()));

        // We need to call another API to add/remove roles for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Auth0 data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        if (roles != null && !roles.isEmpty()) {
            userRoleHandler.addRolesToUser(newUid, roles);
        }

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


        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Uid.NAME)) {
                // Doesn't support to modify 'user_id'
                invalidSchema(delta.getName());

            } else if (delta.getName().equals(Name.NAME)) {
                modifyUser.setEmail(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ENABLE_NAME)) {
                modifyUser.setBlocked(AttributeDeltaUtil.getBooleanValue(delta));

            } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                AttributeDeltaUtil.getGuardedStringValue(delta).access(c -> {
                    modifyUser.setPassword(c);
                });

            } else if (delta.getName().equals(ATTR_ROLES)) {
                rolesToAdd = delta.getValuesToAdd();
                rolesToRemove = delta.getValuesToRemove();

            } else {
                if (!schema.containsKey(delta.getName())) {
                    invalidSchema(delta.getName());
                }
            }
        }

        Request<User> request = client2.users().update(uid.getUidValue(), modifyUser);
        User response = request.execute();

        // We need to call another API to add/remove role for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Cognito data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.
        userRoleHandler.updateRolesToUser(uid, rolesToAdd, rolesToRemove);

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
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }

        Request request = client2.users().delete(uid.getUidValue());
        request.execute();
    }

    private UserType findUserByUid(String uid) {
        ListUsersResponse result = client.listUsers(ListUsersRequest.builder()
                .userPoolId(configuration.getDomain())
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

    public void getUsers(Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) throws Auth0Exception {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null && filter.isByName()) {
            if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
                getUserByPhoneNumber(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            } else {
                getUserByEmail(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            }
            return;
        }

        int pageInitialOffset = resolvePageOffset(options);
        int pageSize = resolvePageSize(configuration, options);

        paging(connector, pageInitialOffset, pageSize, (offset, size) -> {
            UserFilter listFilter = new UserFilter()
                    .withPage(offset, size)
                    .withTotals(true);
            Request<UsersPage> request = client2.users().list(listFilter);
            UsersPage response = request.execute();

            for (User u : response.getItems()) {
                resultsHandler.handle(toConnectorObject(u, attributesToGet, allowPartialAttributeValues));
            }

            return response;
        });
    }

    private void getUserByPhoneNumber(String phoneNumber, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        phoneNumber = phoneNumber.replace("\"", "\\\"");
        UserFilter filter = new UserFilter()
                .withPage(0, 50)
                .withQuery("phone_number\"" + phoneNumber + "\"");
        Request<UsersPage> request = client2.users().list(filter);
        UsersPage response = request.execute();

        for (User user : response.getItems()) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }
    }

    private void getUserByEmail(String email, ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        FieldsFilter filter = new FieldsFilter();
        Request<List<User>> request = client2.users().listByEmail(email, filter);
        List<User> response = request.execute();

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

        // Standard
        if (isNameAttribute(configuration, ATTR_PHONE_NUMBER)) {
            // Returns phoneNumber as _NAME_
            builder.setName(user.getPhoneNumber());
            if (shouldReturn(attributesToGet, ATTR_EMAIL)) {
                builder.addAttribute(ATTR_EMAIL, user.getEmail());
            }
        } else {
            // Returns email as _NAME_
            builder.setName(user.getEmail());
            if (shouldReturn(attributesToGet, ATTR_PHONE_NUMBER)) {
                builder.addAttribute(ATTR_PHONE_NUMBER, user.getPhoneNumber());
            }
        }
        if (shouldReturn(attributesToGet, ATTR_EMAIL_VERIFIED)) {
            builder.addAttribute(ATTR_EMAIL_VERIFIED, user.isEmailVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_PHONE_VERIFIED)) {
            builder.addAttribute(ATTR_PHONE_VERIFIED, user.isPhoneVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_USERNAME)) {
            builder.addAttribute(ATTR_USERNAME, user.getUsername());
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
            // Suppress fetching roles
            LOGGER.ok("Suppress fetching roles because return partial attribute values is requested");

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_ROLES).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching roles default
                LOGGER.ok("Suppress fetching roles because returned by default is true");

            } else if (shouldReturn(attributesToGet, ATTR_ROLES)) {
                // Fetch roles
                LOGGER.ok("Fetching roles because attributes to get is requested");

                List<String> roles = userRoleHandler.getRolesForUser(connector, user.getId());
                builder.addAttribute(ATTR_ROLES, roles);
            }
        }

        return builder.build();
    }
}
