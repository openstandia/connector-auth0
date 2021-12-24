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
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersInGroupIterable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.groupNotFoundError;
import static org.junit.jupiter.api.Assertions.*;

class GroupDeleteTest extends AbstractTest {

    @Test
    void deleteGroup() {
        // Given
        String groupName = "g1";

        mockClient.listUsersInGroup(request -> {
            ListUsersInGroupResponse.Builder builder = ListUsersInGroupResponse.builder()
                    .users(newUserType("user", "sub", "user@example.com"));
            return buildSuccess(builder, ListUsersInGroupResponse.class);
        });

        mockClient.listUsersInGroupPaginator(request -> {
            ListUsersInGroupIterable response = new ListUsersInGroupIterable(mockClient, request);
            return response;
        });

        List<String> removeUser = new ArrayList<>();
        mockClient.adminRemoveUserFromGroup(request -> {
            removeUser.add(request.username());

            return buildSuccess(AdminRemoveUserFromGroupResponse.builder(), AdminRemoveUserFromGroupResponse.class);
        });

        AtomicReference<String> requestedGroupName = new AtomicReference<>();
        mockClient.deleteGroup(request -> {
            requestedGroupName.set(request.groupName());

            return buildSuccess(DeleteGroupResponse.builder(), DeleteGroupResponse.class);
        });

        // When
        connector.delete(Auth0RoleHandler.ROLE_OBJECT_CLASS,
                new Uid(groupName, new Name(groupName)), new OperationOptionsBuilder().build());

        // Then
        assertEquals(groupName, requestedGroupName.get());
        assertEquals(1, removeUser.size());
        assertEquals("user", removeUser.get(0));
    }


    @Test
    void deleteGroupWithNotFoundError() {
        // Given
        String groupName = "g1";

        mockClient.listUsersInGroupPaginator((Function<ListUsersInGroupRequest, ListUsersInGroupIterable>) request -> {
            throw groupNotFoundError();
        });

        // When
        UnknownUidException e = assertThrows(UnknownUidException.class, () -> {
            connector.delete(Auth0RoleHandler.ROLE_OBJECT_CLASS,
                    new Uid(groupName, new Name(groupName)), new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
    }

    private UserType newUserType(String username, String sub, String email) {
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
