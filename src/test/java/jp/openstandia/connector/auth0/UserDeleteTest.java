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
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminDeleteUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminDeleteUserResponse;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static jp.openstandia.connector.auth0.testutil.MockClient.buildSuccess;
import static jp.openstandia.connector.auth0.testutil.MockClient.userNotFoundError;
import static org.junit.jupiter.api.Assertions.*;

class UserDeleteTest extends AbstractTest {

    @Test
    void deleteuser() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";

        AtomicReference<String> requestedUsername = new AtomicReference<>();
        mockClient.adminDeleteUser(request -> {
            requestedUsername.set(request.username());

            return buildSuccess(AdminDeleteUserResponse.builder(), AdminDeleteUserResponse.class);
        });

        // When
        connector.delete(Auth0UserHandler.USER_OBJECT_CLASS,
                new Uid(sub, new Name(username)), new OperationOptionsBuilder().build());

        // Then
        assertEquals(username, requestedUsername.get());
    }

    @Test
    void deleteuserWithNotFoundError() {
        // Given
        String username = "foo";
        String sub = "00000000-0000-0000-0000-000000000001";

        AtomicReference<String> requestedUsername = new AtomicReference<>();
        mockClient.adminDeleteUser((Function<AdminDeleteUserRequest, AdminDeleteUserResponse>) request -> {
            throw userNotFoundError();
        });

        // When
        UnknownUidException e = assertThrows(UnknownUidException.class, () -> {
            connector.delete(Auth0UserHandler.USER_OBJECT_CLASS,
                    new Uid(sub, new Name(username)), new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
    }
}
