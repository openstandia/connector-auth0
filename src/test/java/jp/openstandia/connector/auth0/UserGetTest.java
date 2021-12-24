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
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;

import java.time.Instant;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.userNotFoundError;
import static org.junit.jupiter.api.Assertions.*;

class UserGetTest extends AbstractTest {

    @Test
    void getUser() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String email = "foo@example.com";

        mockClient.adminGetUser(request -> {
            AdminGetUserResponse.Builder builer = AdminGetUserResponse.builder()
                    .username(username)
                    .enabled(true)
                    .userCreateDate(Instant.now())
                    .userLastModifiedDate(Instant.now())
                    .userAttributes(
                            AttributeType.builder()
                                    .name("sub")
                                    .value(sub)
                                    .build(),
                            AttributeType.builder()
                                    .name("email")
                                    .value(email)
                                    .build()
                    );

            return buildSuccess(builer, AdminGetUserResponse.class);
        });

        // When
        ConnectorObject result = connector.getObject(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), new OperationOptionsBuilder().build());

        // Then
        assertEquals(Auth0UserHandler.USER_OBJECT_CLASS, result.getObjectClass());
        assertEquals(sub, result.getUid().getUidValue());
        assertEquals(username, result.getName().getNameValue());
        assertNotNull(result.getAttributeByName("email"));
        assertEquals(email, result.getAttributeByName("email").getValue().get(0));
    }

    @Test
    void getUserWithAttributesToGet() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String email = "foo@example.com";

        mockClient.adminGetUser(request -> {
            AdminGetUserResponse.Builder builer = AdminGetUserResponse.builder()
                    .username(username)
                    .enabled(true)
                    .userCreateDate(Instant.now())
                    .userLastModifiedDate(Instant.now())
                    .userAttributes(
                            AttributeType.builder()
                                    .name("sub")
                                    .value(sub)
                                    .build(),
                            AttributeType.builder()
                                    .name("email")
                                    .value(email)
                                    .build()
                    );

            return buildSuccess(builer, AdminGetUserResponse.class);
        });
        OperationOptions options = new OperationOptionsBuilder()
                .setAttributesToGet(
                        Uid.NAME,
                        Name.NAME,
                        "UserCreateDate"
                ).build();

        // When
        ConnectorObject result = connector.getObject(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), options);

        // Then
        assertEquals(3, result.getAttributes().size());
        assertEquals(sub, result.getUid().getUidValue());
        assertEquals(username, result.getName().getNameValue());
        assertNull(result.getAttributeByName("email"));
        assertNotNull(result.getAttributeByName("UserCreateDate"));
    }

    @Test
    void getUserWithNotFoundError() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";
        String email = "foo@example.com";

        mockClient.adminGetUser((Function<AdminGetUserRequest, AdminGetUserResponse>) request -> {
            throw userNotFoundError();
        });

        // When
        ConnectorObject result = connector.getObject(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), new OperationOptionsBuilder().build());

        // Then
        assertNull(result);
    }
}
