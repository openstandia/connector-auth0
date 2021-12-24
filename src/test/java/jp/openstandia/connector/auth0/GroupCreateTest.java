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

import jp.openstandia.connector.auth0.testutil.AbstractTest;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CreateGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CreateGroupResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.groupExistsError;
import static org.junit.jupiter.api.Assertions.*;

class GroupCreateTest extends AbstractTest {

    @Test
    void createGroup() {
        // Given
        String groupName = "g1";
        String description = "desc";
        Integer precedence = 1;
        String roleArn = "role";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(groupName));
        attrs.add(AttributeBuilder.build("Description", CollectionUtil.newSet(description)));
        attrs.add(AttributeBuilder.build("Precedence", CollectionUtil.newSet(precedence)));
        attrs.add(AttributeBuilder.build("RoleArn", CollectionUtil.newSet(roleArn)));

        mockClient.createGroup(request -> {
            CreateGroupResponse.Builder builder = CreateGroupResponse.builder()
                    .group(newGroupType(groupName, description, precedence, roleArn));
            return buildSuccess(builder, CreateGroupResponse.class);
        });

        // When
        Uid uid = connector.create(Auth0RoleHandler.GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals(groupName, uid.getUidValue());
        assertNull(uid.getNameHint(), "Group shouldn't include Name object in the Uid");
    }

    @Test
    void createGroupWithAlreadyExistsError() {
        // Given
        String groupName = "g1";
        String description = "desc";
        Integer precedence = 1;
        String roleArn = "role";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(groupName));
        attrs.add(AttributeBuilder.build("Description", CollectionUtil.newSet(description)));
        attrs.add(AttributeBuilder.build("Precedence", CollectionUtil.newSet(precedence)));
        attrs.add(AttributeBuilder.build("RoleArn", CollectionUtil.newSet(roleArn)));

        mockClient.createGroup((Function<CreateGroupRequest, CreateGroupResponse>) request -> {
            throw groupExistsError();
        });

        // When
        AlreadyExistsException e = assertThrows(AlreadyExistsException.class, () -> {
            Uid uid = connector.create(Auth0RoleHandler.GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
    }

    private GroupType newGroupType(String groupName, String description, Integer precedence, String roleArn) {
        return GroupType.builder()
                .groupName(groupName)
                .description(description)
                .precedence(precedence)
                .roleArn(roleArn)
                .creationDate(Instant.now())
                .lastModifiedDate(Instant.now())
                .build();
    }
}
