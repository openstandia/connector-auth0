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
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserSearchTest extends AbstractTest {

    @Test
    void getAllUsers() {
        // Given
        mockClient.getUsers = (filter, options, resultHandler) -> {
            Object query = filter.getAsMap().get(QueryFilter.KEY_QUERY);
            assertNotNull(query);
            assertEquals("identities.connection%3A%22Username-Password-Authentication%22",
                    query.toString());

            User user1 = newResponseUser("auth0|001", DEFAULT_CONNECTION);
            user1.setEmail("001@example.com");
            User user2 = newResponseUser("auth0|002", DEFAULT_CONNECTION);
            user2.setEmail("002@example.com");

            resultHandler.apply(user1);
            resultHandler.apply(user2);
        };

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(DEFAULT_USER_OBJECT_CLASS, null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(2, users.size());
        assertEquals(DEFAULT_USER_OBJECT_CLASS, users.get(0).getObjectClass());
        assertEquals("auth0|001", users.get(0).getUid().getUidValue());
        assertEquals("001@example.com", users.get(0).getName().getNameValue());
        assertEquals(DEFAULT_USER_OBJECT_CLASS, users.get(1).getObjectClass());
        assertEquals("auth0|002", users.get(1).getUid().getUidValue());
        assertEquals("002@example.com", users.get(1).getName().getNameValue());
    }

    @Test
    void getAllSMSUsers() {
        // Given
        mockClient.getUsers = (filter, options, resultHandler) -> {
            Object query = filter.getAsMap().get(QueryFilter.KEY_QUERY);
            assertNotNull(query);
            assertEquals("identities.connection%3A%22sms%22",
                    query.toString());

            User user1 = newResponseUser("auth0|001", SMS_CONNECTION);
            user1.setPhoneNumber("+8100000000001");
            User user2 = newResponseUser("auth0|002", SMS_CONNECTION);
            user2.setPhoneNumber("+8100000000002");

            resultHandler.apply(user1);
            resultHandler.apply(user2);
        };

        // When
        List<ConnectorObject> users = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            users.add(connectorObject);
            return true;
        };
        connector.search(SMS_USER_OBJECT_CLASS, null, handler, new OperationOptionsBuilder().build());

        // Then
        assertEquals(2, users.size());
        assertEquals(SMS_USER_OBJECT_CLASS, users.get(0).getObjectClass());
        assertEquals("auth0|001", users.get(0).getUid().getUidValue());
        assertEquals("+8100000000001", users.get(0).getName().getNameValue());
        assertEquals(SMS_USER_OBJECT_CLASS, users.get(1).getObjectClass());
        assertEquals("auth0|002", users.get(1).getUid().getUidValue());
        assertEquals("+8100000000002", users.get(1).getName().getNameValue());
    }
}
