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
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetGroupResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;

import java.time.Instant;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.groupNotFoundError;
import static org.junit.jupiter.api.Assertions.*;

class GroupGetTest extends AbstractTest {

    @Test
    void getGroup() {
        // Given
        String groupName = "g1";
        String description = "desc";
        Integer precedence = 1;
        String roleArn = "role";

        mockClient.getGroup(request -> {
            GetGroupResponse.Builder builer = GetGroupResponse.builder()
                    .group(newGroupType(groupName, description, precedence, roleArn));

            return buildSuccess(builer, GetGroupResponse.class);
        });

        // When
        ConnectorObject result = connector.getObject(Auth0RoleHandler.GROUP_OBJECT_CLASS,
                new Uid(groupName, new Name(groupName)), new OperationOptionsBuilder().build());

        // Then
        assertEquals(Auth0RoleHandler.GROUP_OBJECT_CLASS, result.getObjectClass());
        assertEquals(groupName, result.getUid().getUidValue());
        assertEquals(groupName, result.getName().getNameValue());
        assertNotNull(result.getAttributeByName("CreationDate"));
        assertNotNull(result.getAttributeByName("LastModifiedDate"));
        assertNotNull(result.getAttributeByName("Description"));
        assertEquals(description, result.getAttributeByName("Description").getValue().get(0));
        assertNotNull(result.getAttributeByName("Precedence"));
        assertEquals(precedence, result.getAttributeByName("Precedence").getValue().get(0));
        assertNotNull(result.getAttributeByName("RoleArn"));
        assertEquals(roleArn, result.getAttributeByName("RoleArn").getValue().get(0));
    }

    @Test
    void getGroupWithAttributesToGet() {
        // Given
        String groupName = "g1";
        String description = "desc";
        Integer precedence = 1;
        String roleArn = "role";

        mockClient.getGroup(request -> {
            GetGroupResponse.Builder builer = GetGroupResponse.builder()
                    .group(newGroupType(groupName, description, precedence, roleArn));

            return buildSuccess(builer, GetGroupResponse.class);
        });
        OperationOptions options = new OperationOptionsBuilder()
                .setAttributesToGet(
                        Uid.NAME,
                        Name.NAME,
                        "CreationDate"
                ).build();

        // When
        ConnectorObject result = connector.getObject(Auth0RoleHandler.GROUP_OBJECT_CLASS,
                new Uid(groupName, new Name(groupName)), options);

        // Then
        assertEquals(Auth0RoleHandler.GROUP_OBJECT_CLASS, result.getObjectClass());
        assertEquals(3, result.getAttributes().size());
        assertEquals(groupName, result.getUid().getUidValue());
        assertEquals(groupName, result.getName().getNameValue());
        assertNotNull(result.getAttributeByName("CreationDate"));
        assertNull(result.getAttributeByName("Description"));
        assertNull(result.getAttributeByName("Precedence"));
        assertNull(result.getAttributeByName("RoleArn"));
    }


    @Test
    void getGroupWithNotFoundError() {
        // Given
        String groupName = "g1";
        String description = "desc";
        Integer precedence = 1;
        String roleArn = "role";

        mockClient.getGroup((Function<GetGroupRequest, GetGroupResponse>) request -> {
            throw groupNotFoundError();
        });

        // When
        ConnectorObject result = connector.getObject(Auth0RoleHandler.GROUP_OBJECT_CLASS,
                new Uid(groupName, new Name(groupName)), new OperationOptionsBuilder().build());

        // Then
        assertNull(result);
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
