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

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class UserUpdateTest extends AbstractTest {

    @Override
    protected Auth0Configuration newConfiguration() {
        Auth0Configuration conf = super.newConfiguration();
        conf.setAppMetadataSchema(new String[]{"text1$string", "text2$stringArray",});
        return conf;
    }

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
        Set<AttributeDelta> result = connector.updateDelta(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertTrue(patchUser.isBlocked());
    }

    @Test
    void deleteAppMetadataSingleValue() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        Set<AttributeDelta> delta = new HashSet<>();
        delta.add(AttributeDeltaBuilder.build("app_metadata.text1", (String) null));

        AtomicReference<User> updated = new AtomicReference<>();
        mockClient.getUserByUid = ((uid, filter) -> {
            User user = new User();
            user.setId(userId);
            Map<String, Object> currentAppMetadata = new HashMap<>();
            currentAppMetadata.put("text", "a");
            user.setAppMetadata(currentAppMetadata);
            return user;
        });
        mockClient.updateUser = ((uid, patchUser) -> {
            updated.set(patchUser);
            return;
        });

        // When
        Set<AttributeDelta> result = connector.updateDelta(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertFalse(patchUser.getAppMetadata().isEmpty());
        assertEquals(1, patchUser.getAppMetadata().size());
        assertTrue(patchUser.getAppMetadata().containsKey("text1"));
        assertNull(patchUser.getAppMetadata().get("text1"));
    }

    @Test
    void deleteAppMetadataMultipleValues() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        Set<AttributeDelta> delta = new HashSet<>();
        delta.add(AttributeDeltaBuilder.build("app_metadata.text2", null, Arrays.asList("a")));

        AtomicReference<User> updated = new AtomicReference<>();
        mockClient.getUserByUid = ((uid, filter) -> {
            User user = new User();
            user.setId(userId);
            Map<String, Object> currentAppMetadata = new HashMap<>();
            List<String> values = new ArrayList<>();
            values.add("a");
            values.add("b");
            currentAppMetadata.put("text2", values);
            user.setAppMetadata(currentAppMetadata);
            return user;
        });
        mockClient.updateUser = ((uid, patchUser) -> {
            updated.set(patchUser);
            return;
        });

        // When
        Set<AttributeDelta> result = connector.updateDelta(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertFalse(patchUser.getAppMetadata().isEmpty());
        assertEquals(1, patchUser.getAppMetadata().size());
        assertTrue(patchUser.getAppMetadata().containsKey("text2"));
        assertEquals(1, ((List) patchUser.getAppMetadata().get("text2")).size());
        assertEquals("b", ((List) patchUser.getAppMetadata().get("text2")).get(0));
    }

    @Test
    void deleteAppMetadataMultipleValuesAll() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        Set<AttributeDelta> delta = new HashSet<>();
        delta.add(AttributeDeltaBuilder.build("app_metadata.text2", null, Arrays.asList("a", "b")));

        AtomicReference<User> updated = new AtomicReference<>();
        mockClient.getUserByUid = ((uid, filter) -> {
            User user = new User();
            user.setId(userId);
            Map<String, Object> currentAppMetadata = new HashMap<>();
            List<String> values = new ArrayList<>();
            values.add("a");
            values.add("b");
            currentAppMetadata.put("text2", values);
            user.setAppMetadata(currentAppMetadata);
            return user;
        });
        mockClient.updateUser = ((uid, patchUser) -> {
            updated.set(patchUser);
            return;
        });

        // When
        Set<AttributeDelta> result = connector.updateDelta(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertEquals(1, patchUser.getAppMetadata().size());
        assertTrue(patchUser.getAppMetadata().containsKey("text2"));
        assertNull(patchUser.getAppMetadata().get("text2"));
    }


    @Test
    void deleteAppMetadataAllMultiValuesAllButSingleValueRemains() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";

        Set<AttributeDelta> delta = new HashSet<>();
        delta.add(AttributeDeltaBuilder.build("app_metadata.text2", null, Arrays.asList("a", "b")));

        AtomicReference<User> updated = new AtomicReference<>();
        mockClient.getUserByUid = ((uid, filter) -> {
            User user = new User();
            user.setId(userId);
            Map<String, Object> currentAppMetadata = new HashMap<>();
            currentAppMetadata.put("text1", "a");
            List<String> values = new ArrayList<>();
            values.add("a");
            values.add("b");
            currentAppMetadata.put("text2", values);
            user.setAppMetadata(currentAppMetadata);
            return user;
        });
        mockClient.updateUser = ((uid, patchUser) -> {
            updated.set(patchUser);
            return;
        });

        // When
        Set<AttributeDelta> result = connector.updateDelta(DEFAULT_USER_OBJECT_CLASS, new Uid(userId), delta, new OperationOptionsBuilder().build());

        // Then
        assertNull(result);

        User patchUser = updated.get();
        assertEquals(2, patchUser.getAppMetadata().size());
        assertTrue(patchUser.getAppMetadata().containsKey("text1"));
        assertTrue(patchUser.getAppMetadata().containsKey("text2"));
        assertEquals("a", patchUser.getAppMetadata().get("text1"));
        assertNull(patchUser.getAppMetadata().get("text2"));
    }
}
