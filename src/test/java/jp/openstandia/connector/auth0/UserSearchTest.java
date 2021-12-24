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
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserStatusType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersIterable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UserSearchTest extends AbstractTest {

    @Test
    void getAllUsers() {
        // Given
        mockClient.listUsersPaginator(request -> {
            ListUsersIterable response = new ListUsersIterable(mockClient, request);
            return response;
        });

        mockClient.listUsers(request -> {
            ListUsersResponse.Builder builer = ListUsersResponse.builder()
                    .users(
                            newUserType("sub1", "user1", "user1@example.com"),
                            newUserType("sub2", "user2", "user2@example.com")
                    );

            return buildSuccess(builer, ListUsersResponse.class);
        });

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(Auth0UserHandler.USER_OBJECT_CLASS,
                null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(2, users.size());
        assertEquals(Auth0UserHandler.USER_OBJECT_CLASS, users.get(0).getObjectClass());
        assertEquals("sub1", users.get(0).getUid().getUidValue());
        assertEquals("user1", users.get(0).getName().getNameValue());
        assertEquals("user1@example.com", users.get(0).getAttributeByName("email").getValue().get(0));
        assertEquals(Auth0UserHandler.USER_OBJECT_CLASS, users.get(1).getObjectClass());
        assertEquals("sub2", users.get(1).getUid().getUidValue());
        assertEquals("user2", users.get(1).getName().getNameValue());
        assertEquals("user2@example.com", users.get(1).getAttributeByName("email").getValue().get(0));
    }

    @Test
    void getAllUsersWithNotFound() {
        // Given
        mockClient.listUsersPaginator(request -> {
            ListUsersIterable response = new ListUsersIterable(mockClient, request);
            return response;
        });

        mockClient.listUsers(request -> {
            ListUsersResponse.Builder builer = ListUsersResponse.builder();

            return buildSuccess(builer, ListUsersResponse.class);
        });

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(Auth0UserHandler.USER_OBJECT_CLASS,
                null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(0, users.size());
    }

    private UserType newUserType(String sub, String username, String email) {
        return UserType.builder()
                .username(username)
                .enabled(true)
                .userStatus(UserStatusType.FORCE_CHANGE_PASSWORD)
                .userCreateDate(Instant.now())
                .userLastModifiedDate(Instant.now())
                .attributes(
                        AttributeType.builder()
                                .name("sub")
                                .value(sub)
                                .build(),
                        AttributeType.builder()
                                .name("email")
                                .value(email)
                                .build()
                )
                .build();
    }
}
