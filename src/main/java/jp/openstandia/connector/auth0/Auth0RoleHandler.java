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
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.RetryableException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListGroupsIterable;

import java.util.List;
import java.util.Set;

import static jp.openstandia.connector.auth0.Auth0Utils.*;

public class Auth0RoleHandler {

    public static final ObjectClass ROLE_OBJECT_CLASS = new ObjectClass("Role");

    private static final Log LOGGER = Log.getLog(Auth0RoleHandler.class);

    // Unique and unchangeable within the user pool
    private static final String ATTR_ROLE_NAME = "name";

    // Attributes
    private static final String ATTR_DESCRIPTION = "description";

    private final Auth0Configuration configuration;
    private final CognitoIdentityProviderClient client;
    private final Auth0AssociationHandler userGroupHandler;

    public Auth0RoleHandler(Auth0Configuration configuration, CognitoIdentityProviderClient client) {
        this.configuration = configuration;
        this.client = client;
        this.userGroupHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getGroupSchema(Auth0Configuration config) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(ROLE_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(true)
                .setUpdateable(false)
                .setNativeName(ATTR_ROLE_NAME)
                .build());
        // __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(false)
                .setNativeName(ATTR_ROLE_NAME)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DESCRIPTION)
                .build());

        ObjectClassInfo roleSchemaInfo = builder.build();

        LOGGER.info("The constructed Role schema: {0}", roleSchemaInfo);

        return roleSchemaInfo;
    }

    /**
     * The spec for create a role:
     * https://auth0.com/docs/api/management/v2/#!/Roles/post_roles
     *
     * @param attributes
     * @return
     * @throws AlreadyExistsException Object with the specified _NAME_ already exists.
     *                                Or there is a similar violation in any of the object attributes that
     *                                cannot be distinguished from AlreadyExists situation.
     */
    public Uid createRole(Set<Attribute> attributes) throws AlreadyExistsException {
        if (attributes == null || attributes.isEmpty()) {
            throw new InvalidAttributeValueException("attributes not provided or empty");
        }
        GroupModel newGroup = new GroupModel();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newGroup.applyGroupName(attr);

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newGroup.applyDescription(attr);

            } else {
                invalidSchema(attr.getName());
            }
        }

        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(configuration.getDomain())
                .groupName(newGroup.groupName)
                .description(newGroup.description)
                .precedence(newGroup.precedence)
                .roleArn(newGroup.roleArn)
                .build();

        CreateGroupResponse result = null;
        try {
            result = client.createGroup(request);

            checkCognitoResult(result, "CreateGroup");
        } catch (GroupExistsException e) {
            LOGGER.warn(e, "The group already exists when creating. uid: {0}", request.groupName());
            throw new AlreadyExistsException("The group exists. GroupName: " + request.groupName(), e);
        }

        GroupType group = result.group();

        // Caution! Don't include Name object in the Uid
        // because it throws SchemaException with "No definition for ConnId NAME attribute found in definition crOCD
        // ({http://midpoint.evolveum.com/xml/ns/public/resource/instance-3}Group)".
        Uid newUid = new Uid(group.groupName());

        return newUid;
    }

    /**
     * The spec for UpdateGroup:
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateGroup.html
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        GroupModel modifyGroup = new GroupModel();

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(ATTR_DESCRIPTION)) {
                modifyGroup.applyDescription(delta);

            } else {
                invalidSchema(delta.getName());
            }
        }

        if (modifyGroup.description != null ||
                modifyGroup.precedence != null ||
                modifyGroup.roleArn != null) {
            try {
                UpdateGroupRequest request = UpdateGroupRequest.builder()
                        .userPoolId(configuration.getDomain())
                        .groupName(uid.getUidValue())
                        .description(modifyGroup.description)
                        .precedence(modifyGroup.precedence)
                        .roleArn(modifyGroup.roleArn)
                        .build();

                UpdateGroupResponse result = client.updateGroup(request);

                checkCognitoResult(result, "UpdateGroup");
            } catch (ResourceNotFoundException e) {
                LOGGER.warn("Not found group when updating. uid: {0}", uid);
                throw new UnknownUidException(uid, ROLE_OBJECT_CLASS);
            }
        }

        return null;
    }

    private class GroupModel {
        String groupName;
        String description;
        Integer precedence;
        String roleArn;
        List<Object> addUsers;
        List<Object> removeUsers;

        public void applyGroupName(Attribute attr) {
            this.groupName = AttributeUtil.getAsStringValue(attr);
        }

        void applyDescription(Attribute attr) {
            this.description = AttributeUtil.getAsStringValue(attr);
        }

        void applyDescription(AttributeDelta delta) {
            if (delta.getValuesToReplace().isEmpty()) {
                // Try to remove Description by setting "".
                // But it doesn't work currently due to Cognito limitation...?
                this.description = "";
            } else {
                this.description = AttributeDeltaUtil.getAsStringValue(delta);
            }
        }

        void applyPrecedence(Attribute attr) {
            this.precedence = AttributeUtil.getIntegerValue(attr);
        }

        void applyPrecedence(AttributeDelta delta) {
            if (delta.getValuesToReplace().isEmpty()) {
                // Precedence is removed if we set 0
                this.precedence = 0;
            } else {
                this.precedence = AttributeDeltaUtil.getIntegerValue(delta);
            }
        }

        void applyRoleArn(Attribute attr) {
            this.roleArn = AttributeUtil.getAsStringValue(attr);
        }

        void applyRoleArn(AttributeDelta delta) {
            if (delta.getValuesToReplace().isEmpty()) {
                // Try to remove RoleArn by setting "".
                // But it doesn't work currently due to Cognito limitation...?
                this.roleArn = "";
            } else {
                this.roleArn = AttributeDeltaUtil.getAsStringValue(delta);
            }
        }

        void applyUsers(Attribute attr) {
            this.addUsers.addAll(attr.getValue());
        }

        void applyUsers(AttributeDelta delta) {
            if (delta.getValuesToAdd() != null) {
                this.addUsers.addAll(delta.getValuesToAdd());
            }
            if (delta.getValuesToRemove() != null) {
                this.removeUsers.addAll(delta.getValuesToRemove());
            }
        }
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/delete_roles_by_id
     *
     * @param objectClass
     * @param uid
     * @param options
     */
    public void deleteRole(ObjectClass objectClass, Uid uid, OperationOptions options) {
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }

        try {
            DeleteGroupResponse result = client.deleteGroup(DeleteGroupRequest.builder()
                    .userPoolId(configuration.getDomain())
                    .groupName(uid.getUidValue()).build());

            checkCognitoResult(result, "DeleteGroup");
        } catch (ResourceNotFoundException e) {
            LOGGER.warn("Not found group when deleting. uid: {0}", uid);
            throw new UnknownUidException(uid, objectClass);
        }
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2/#!/Roles/get_roles
     *
     * @param filter
     * @param resultsHandler
     * @param options
     */
    public void getRoles(Auth0Filter filter,
                         ResultsHandler resultsHandler, OperationOptions options) {
        if (filter != null && (filter.isByName() || filter.isByUid())) {
            getGroupByName(filter.attributeValue, resultsHandler, options);
            return;
        }

        // Cannot filter using Cognito API unfortunately...
        // So we always return all groups here.
        ListGroupsRequest.Builder request = ListGroupsRequest.builder();
        request.userPoolId(configuration.getDomain());

        ListGroupsIterable result = client.listGroupsPaginator(request.build());

        result.forEach(r -> r.groups().forEach(g -> resultsHandler.handle(toConnectorObject(g, options))));
    }

    private void getGroupByName(String groupName,
                                ResultsHandler resultsHandler, OperationOptions options) {
        GetGroupResponse result = client.getGroup(GetGroupRequest.builder()
                .userPoolId(configuration.getDomain())
                .groupName(groupName).build());

        checkCognitoResult(result, "GetGroup");

        resultsHandler.handle(toConnectorObject(result.group(), options));
    }

    private ConnectorObject toConnectorObject(GroupType g, OperationOptions options) {
        String[] attributesToGet = options.getAttributesToGet();
        if (attributesToGet == null) {
            return toFullConnectorObject(g);
        }

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(ROLE_OBJECT_CLASS)
                .setUid(g.groupName())
                .setName(g.groupName());

        for (String getAttr : attributesToGet) {
            if (getAttr.equals(ATTR_DESCRIPTION)) {
                builder.addAttribute(ATTR_DESCRIPTION, g.description());
            }
        }

        return builder.build();
    }

    private ConnectorObject toFullConnectorObject(GroupType g) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(ROLE_OBJECT_CLASS)
                .setUid(new Uid(g.groupName(), new Name(g.groupName())))
                .setName(g.groupName())
                .addAttribute(ATTR_DESCRIPTION, g.description());

        return builder.build();
    }
}
