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

import com.auth0.json.mgmt.users.User;
import jp.openstandia.connector.auth0.testutil.AbstractTest;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserUpdateTest extends AbstractTest {

    @Test
    void disableUser() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        Set<AttributeDelta> delta = new HashSet<>();
        delta.add(AttributeDeltaBuilder.buildEnabled(false));

        AtomicReference<User> updated = new AtomicReference<>();
        mockClient.updateUser = ((uid, patchUser) -> {
            updated.set(patchUser);
            return;
        });

        // When
        Set<AttributeDelta> result = connector.updateDelta(Auth0UserHandler.USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertTrue(patchUser.isBlocked());
    }
}
