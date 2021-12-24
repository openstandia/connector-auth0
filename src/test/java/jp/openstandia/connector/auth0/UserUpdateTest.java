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
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.userNotFoundError;
import static org.junit.jupiter.api.Assertions.*;

class UserUpdateTest extends AbstractTest {

    @Test
    void updateUser() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String newEmail = "bar@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("email", CollectionUtil.newSet(newEmail)));

        AtomicReference<Optional<String>> requestedNewEmail = new AtomicReference<>();
        mockClient.adminUpdateUserAttributes(request -> {
            requestedNewEmail.set(request.userAttributes().stream()
                    .filter(a -> a.name().equals("email"))
                    .map(a -> a.value())
                    .findFirst());

            AdminUpdateUserAttributesResponse.Builder builder = AdminUpdateUserAttributesResponse.builder();
            return buildSuccess(builder, AdminUpdateUserAttributesResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertNotNull(requestedNewEmail.get());
        assertEquals(newEmail, requestedNewEmail.get().get());
    }

    @Test
    void updateUserWithDisabled() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String newEmail = "bar@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("email", CollectionUtil.newSet(newEmail)));
        modifications.add(AttributeDeltaBuilder.buildEnabled(false));

        AtomicReference<Optional<String>> requestedNewEmail = new AtomicReference<>();
        mockClient.adminUpdateUserAttributes(request -> {
            requestedNewEmail.set(request.userAttributes().stream()
                    .filter(a -> a.name().equals("email"))
                    .map(a -> a.value())
                    .findFirst());

            AdminUpdateUserAttributesResponse.Builder builder = AdminUpdateUserAttributesResponse.builder();
            return buildSuccess(builder, AdminUpdateUserAttributesResponse.class);
        });
        mockClient.adminDisableUser(request -> {
            return buildSuccess(AdminDisableUserResponse.builder(), AdminDisableUserResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertNotNull(requestedNewEmail.get());
        assertEquals(newEmail, requestedNewEmail.get().get());
    }

    @Test
    void updateUserWithPassword() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String newEmail = "bar@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("email", CollectionUtil.newSet(newEmail)));
        modifications.add(AttributeDeltaBuilder.buildPassword("secret".toCharArray()));

        AtomicReference<Optional<String>> requestedNewEmail = new AtomicReference<>();
        mockClient.adminUpdateUserAttributes(request -> {
            requestedNewEmail.set(request.userAttributes().stream()
                    .filter(a -> a.name().equals("email"))
                    .map(a -> a.value())
                    .findFirst());

            AdminUpdateUserAttributesResponse.Builder builder = AdminUpdateUserAttributesResponse.builder();
            return buildSuccess(builder, AdminUpdateUserAttributesResponse.class);
        });
        AtomicReference<String> requestedNewPassword = new AtomicReference<>();
        AtomicReference<Boolean> requestedPasswordPermanent = new AtomicReference<>();
        mockClient.adminSetUserPassword(request -> {
            requestedNewPassword.set(request.password());
            requestedPasswordPermanent.set(request.permanent());

            return buildSuccess(AdminSetUserPasswordResponse.builder(), AdminSetUserPasswordResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertNotNull(requestedNewEmail.get());
        assertEquals(newEmail, requestedNewEmail.get().get());
        assertEquals("secret", requestedNewPassword.get());
        assertNull(requestedPasswordPermanent.get());
    }

    @Test
    void updateUserPasswordOnly() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.buildPassword("secret".toCharArray()));
        modifications.add(AttributeDeltaBuilder.build("password_permanent", CollectionUtil.newSet(true)));

        AtomicReference<String> requestedNewPassword = new AtomicReference<>();
        AtomicReference<Boolean> requestedPasswordPermanent = new AtomicReference<>();
        mockClient.adminSetUserPassword(request -> {
            requestedNewPassword.set(request.password());
            requestedPasswordPermanent.set(request.permanent());

            return buildSuccess(AdminSetUserPasswordResponse.builder(), AdminSetUserPasswordResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertEquals("secret", requestedNewPassword.get());
        assertTrue(requestedPasswordPermanent.get());
    }

    @Test
    void updateUserWithAddGroup() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String groupName = "g1";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("groups", CollectionUtil.newSet(groupName), null));

        AtomicReference<String> requestedUsername = new AtomicReference<>();
        AtomicReference<String> requestedGroupName = new AtomicReference<>();
        mockClient.adminAddUserToGroup(request -> {
            requestedUsername.set(request.username());
            requestedGroupName.set(request.groupName());

            return buildSuccess(AdminAddUserToGroupResponse.builder(), AdminAddUserToGroupResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertEquals(username, requestedUsername.get());
        assertEquals(groupName, requestedGroupName.get());
    }

    @Test
    void updateUserWithRemoveGroup() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String groupName = "g1";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("groups", null, CollectionUtil.newSet(groupName)));

        AtomicReference<String> requestedUsername = new AtomicReference<>();
        AtomicReference<String> requestedGroupName = new AtomicReference<>();
        mockClient.adminRemoveUserFromGroup(request -> {
            requestedUsername.set(request.username());
            requestedGroupName.set(request.groupName());

            return buildSuccess(AdminRemoveUserFromGroupResponse.builder(), AdminRemoveUserFromGroupResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertEquals(username, requestedUsername.get());
        assertEquals(groupName, requestedGroupName.get());
    }

    @Test
    void updateUserWithMultipleAddAndRemoveGroup() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String addGroup1 = "g1";
        String addGroup2 = "g2";
        String removeGroup1 = "g3";
        String removeGroup2 = "g4";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("groups",
                CollectionUtil.newSet(addGroup1, addGroup2),
                CollectionUtil.newSet(removeGroup1, removeGroup2)));

        List<String> addGroup = new ArrayList<>();
        mockClient.adminAddUserToGroup(request -> {
            addGroup.add(request.groupName());

            return buildSuccess(AdminAddUserToGroupResponse.builder(), AdminAddUserToGroupResponse.class);
        });

        List<String> removeGroup = new ArrayList<>();
        mockClient.adminRemoveUserFromGroup(request -> {
            removeGroup.add(request.groupName());

            return buildSuccess(AdminRemoveUserFromGroupResponse.builder(), AdminRemoveUserFromGroupResponse.class);
        });

        // When
        Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());

        // Then
        assertEquals(2, addGroup.size());
        assertEquals(2, removeGroup.size());
        assertEquals(addGroup1, addGroup.get(0));
        assertEquals(addGroup2, addGroup.get(1));
        assertEquals(removeGroup1, removeGroup.get(0));
        assertEquals(removeGroup2, removeGroup.get(1));
    }

    @Test
    void updateUserWithNotFoundError() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String newEmail = "bar@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("email", CollectionUtil.newSet(newEmail)));

        mockClient.adminUpdateUserAttributes((Function<AdminUpdateUserAttributesRequest, AdminUpdateUserAttributesResponse>) request -> {
            throw userNotFoundError();
        });

        // When
        UnknownUidException e = assertThrows(UnknownUidException.class, () -> {
            Set<AttributeDelta> updated = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS,
                    new Uid(sub, new Name(username)), modifications, new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
    }
}
