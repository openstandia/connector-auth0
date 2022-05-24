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
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserDeleteTest extends AbstractTest {

    @Test
    void deleteUser() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        AtomicReference<Boolean> called = new AtomicReference<>();
        mockClient.deleteUser = uid -> {
            assertEquals(userId, uid.getUidValue());
            called.set(true);
            return;
        };

        // When
        connector.delete(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), new OperationOptionsBuilder().build());

        // Then
        assertTrue(called.get());
    }
}
