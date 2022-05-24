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

import com.auth0.client.mgmt.filter.QueryFilter;
import com.auth0.json.mgmt.users.User;
import jp.openstandia.connector.auth0.testutil.AbstractTest;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserGetTest extends AbstractTest {

    @Test
    void getUserByUid() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String email = "test@example.com";

        mockClient.getUserByUid = (reqUserId, filter) -> {
            User user = newResponseUser(reqUserId, DEFAULT_CONNECTION);
            user.setEmail(email);
            return user;
        };

        // When
        ConnectorObject result = connector.getObject(DEFAULT_USER_OBJECT_CLASS,
                new Uid(userId), new OperationOptionsBuilder().build());

        // Then
        assertEquals(DEFAULT_USER_OBJECT_CLASS, result.getObjectClass());
        assertEquals(userId, result.getUid().getUidValue());
        assertEquals(email, result.getName().getNameValue());
    }

    @Test
    void getUserByEmail() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String email = "test@example.com";

        mockClient.getUsersByFilter = (filter -> {
            Object query = filter.getAsMap().get(QueryFilter.KEY_QUERY);
            assertNotNull(query);
            assertEquals("identities.connection%3A%22Username-Password-Authentication%22+AND+email%3A%22test%40example.com%22",
                    query.toString());

            User user = newResponseUser(userId, DEFAULT_CONNECTION);
            user.setEmail(email);
            return Stream.of(user).collect(Collectors.toList());
        });

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(DEFAULT_USER_OBJECT_CLASS, FilterBuilder.equalTo(new Name(email)), handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(1, users.size());
        assertEquals(DEFAULT_USER_OBJECT_CLASS, users.get(0).getObjectClass());
        assertEquals(userId, users.get(0).getUid().getUidValue());
        assertEquals(email, users.get(0).getName().getNameValue());
    }

    @Test
    void getUserByPhoneNumber() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String phoneNumber = "+817000000000";

        mockClient.getUsersByFilter = (filter -> {
            Object query = filter.getAsMap().get(QueryFilter.KEY_QUERY);
            assertNotNull(query);
            assertEquals("identities.connection%3A%22sms%22+AND+phone_number%3A%22%2B817000000000%22",
                    query.toString());

            User user = newResponseUser(userId, SMS_CONNECTION);
            user.setPhoneNumber(phoneNumber);
            return Stream.of(user).collect(Collectors.toList());
        });

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(SMS_USER_OBJECT_CLASS, FilterBuilder.equalTo(new Name(phoneNumber)), handler, new OperationOptionsBuilder().build());


        // Then
        assertEquals(1, users.size());
        assertEquals(SMS_USER_OBJECT_CLASS, users.get(0).getObjectClass());
        assertEquals(userId, users.get(0).getUid().getUidValue());
        assertEquals(phoneNumber, users.get(0).getName().getNameValue());
    }
}
