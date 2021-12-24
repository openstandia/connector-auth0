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
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListGroupsIterable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static org.junit.jupiter.api.Assertions.assertEquals;

class GroupSearchTest extends AbstractTest {

    @Test
    void getAllUsers() {
        // Given
        mockClient.listGroupsPaginator(request -> {
            ListGroupsIterable response = new ListGroupsIterable(mockClient, request);
            return response;
        });

        mockClient.listGroups(request -> {
            ListGroupsResponse.Builder builer = ListGroupsResponse.builder()
                    .groups(
                            newGroupType("g1", "desc1", 1, "role1"),
                            newGroupType("g2", "desc2", 2, "role2")
                    );

            return buildSuccess(builer, ListGroupsResponse.class);
        });

        // When
        List<ConnectorObject> groups = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            groups.add(connectorObject);
            return true;
        };
        connector.search(Auth0RoleHandler.ROLE_OBJECT_CLASS,
                null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(2, groups.size());
        assertEquals(Auth0RoleHandler.ROLE_OBJECT_CLASS, groups.get(0).getObjectClass());
        assertEquals("g1", groups.get(0).getUid().getUidValue());
        assertEquals("g1", groups.get(0).getName().getNameValue());
        assertEquals("desc1", groups.get(0).getAttributeByName("Description").getValue().get(0));
        assertEquals(1, groups.get(0).getAttributeByName("Precedence").getValue().get(0));
        assertEquals("role1", groups.get(0).getAttributeByName("RoleArn").getValue().get(0));
        assertEquals(Auth0RoleHandler.ROLE_OBJECT_CLASS, groups.get(1).getObjectClass());
        assertEquals("g2", groups.get(1).getUid().getUidValue());
        assertEquals("g2", groups.get(1).getName().getNameValue());
        assertEquals("desc2", groups.get(1).getAttributeByName("Description").getValue().get(0));
        assertEquals(2, groups.get(1).getAttributeByName("Precedence").getValue().get(0));
        assertEquals("role2", groups.get(1).getAttributeByName("RoleArn").getValue().get(0));
    }

    @Test
    void getAllUsersWithNotFound() {
        // Given
        mockClient.listGroupsPaginator(request -> {
            ListGroupsIterable response = new ListGroupsIterable(mockClient, request);
            return response;
        });

        mockClient.listGroups(request -> {
            ListGroupsResponse.Builder builer = ListGroupsResponse.builder();

            return buildSuccess(builer, ListGroupsResponse.class);
        });

        // When
        List<ConnectorObject> groups = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            groups.add(connectorObject);
            return true;
        };
        connector.search(Auth0RoleHandler.ROLE_OBJECT_CLASS,
                null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(0, groups.size());
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
