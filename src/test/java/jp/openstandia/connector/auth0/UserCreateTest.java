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
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.userExistsError;
import static org.junit.jupiter.api.Assertions.*;

class UserCreateTest extends AbstractTest {

    @Test
    void createUser() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(username));
        attrs.add(AttributeBuilder.build("email", CollectionUtil.newSet(email)));

        mockClient.adminCreateUser((request) -> {
            AdminCreateUserResponse.Builder builder = AdminCreateUserResponse.builder()
                    .user(newUserType(sub, username, email));
            return buildSuccess(builder, AdminCreateUserResponse.class);
        });

        // When
        Uid uid = connector.create(Auth0UserHandler.USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals(sub, uid.getUidValue());
        assertEquals(username, uid.getNameHintValue());
    }

    @Test
    void createUserWithDisabled() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(username));
        attrs.add(AttributeBuilder.build("email", CollectionUtil.newSet(email)));
        attrs.add(AttributeBuilder.buildEnabled(false));

        mockClient.adminCreateUser(request -> {
            AdminCreateUserResponse.Builder builder = AdminCreateUserResponse.builder()
                    .user(newUserType(sub, username, email));
            return buildSuccess(builder, AdminCreateUserResponse.class);
        });
        mockClient.adminDisableUser(request -> {
            return buildSuccess(AdminDisableUserResponse.builder(), AdminDisableUserResponse.class);
        });

        // When
        Uid uid = connector.create(Auth0UserHandler.USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals("00000000-0000-0000-0000-000000000001", uid.getUidValue());
        assertEquals("foo", uid.getNameHintValue());
    }

    @Test
    void createUserWithPassword() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(username));
        attrs.add(AttributeBuilder.build("email", CollectionUtil.newSet(email)));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));

        mockClient.adminCreateUser(request -> {
            AdminCreateUserResponse.Builder builder = AdminCreateUserResponse.builder()
                    .user(newUserType(sub, username, email));
            return buildSuccess(builder, AdminCreateUserResponse.class);
        });
        mockClient.adminSetUserPassword(request -> {
            return buildSuccess(AdminSetUserPasswordResponse.builder(), AdminSetUserPasswordResponse.class);
        });

        // When
        Uid uid = connector.create(Auth0UserHandler.USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals("00000000-0000-0000-0000-000000000001", uid.getUidValue());
        assertEquals("foo", uid.getNameHintValue());
    }

    @Test
    void createUserWithAlreadyExistsError() {
        // Given
        String username = "foo";
        String email = "foo@example.com";
        String sub = "00000000-0000-0000-0000-000000000001";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(username));
        attrs.add(AttributeBuilder.build("email", CollectionUtil.newSet(email)));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));

        mockClient.adminCreateUser((Function<AdminCreateUserRequest, AdminCreateUserResponse>) request -> {
            throw userExistsError();
        });

        // When
        AlreadyExistsException e = assertThrows(AlreadyExistsException.class, () -> {
            Uid uid = connector.create(Auth0UserHandler.USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
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
