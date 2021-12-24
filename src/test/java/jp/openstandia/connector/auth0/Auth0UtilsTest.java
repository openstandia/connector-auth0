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

import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class Auth0UtilsTest {

    @Test
    void toConnectorAttribute() {
        Attribute string = Auth0Utils.toConnectorAttribute(
                AttributeInfoBuilder.define("string").setType(String.class).build(),
                AttributeType.builder().name("string").value("test").build());

        assertEquals("string", string.getName());
        assertEquals(1, string.getValue().size());
        assertEquals("test", string.getValue().get(0));

        Attribute integer = Auth0Utils.toConnectorAttribute(
                AttributeInfoBuilder.define("int").setType(Integer.class).build(),
                AttributeType.builder().name("int").value("1").build());

        assertEquals("int", integer.getName());
        assertEquals(1, integer.getValue().size());
        assertEquals(1, integer.getValue().get(0));

        Attribute date = Auth0Utils.toConnectorAttribute(
                AttributeInfoBuilder.define("date").setType(ZonedDateTime.class).build(),
                AttributeType.builder().name("date").value("2007-12-03").build());

        assertEquals("date", date.getName());
        assertEquals(1, date.getValue().size());
        assertEquals(LocalDateTime.parse("2007-12-03T00:00:00").atZone(ZoneId.systemDefault()),
                date.getValue().get(0));
    }

    @Test
    void toCognitoAttribute() {
        Map<String, AttributeInfo> schema = new HashMap<>();
        schema.put("string", AttributeInfoBuilder.define("string").setType(String.class).build());
        schema.put("int", AttributeInfoBuilder.define("int").setType(Integer.class).build());
        schema.put("date", AttributeInfoBuilder.define("date").setType(ZonedDateTime.class).build());
        schema.put("bool", AttributeInfoBuilder.define("bool").setType(Boolean.class).build());

        assertEquals("test",
                Auth0Utils.toCognitoAttribute(schema,
                        AttributeBuilder.build("string", "test"))
                        .value()
        );
        assertEquals("1",
                Auth0Utils.toCognitoAttribute(schema,
                        AttributeBuilder.build("int", 1))
                        .value()
        );
        assertEquals("2007-12-03",
                Auth0Utils.toCognitoAttribute(schema,
                        AttributeBuilder.build("date",
                                LocalDateTime.parse("2007-12-03T10:15:30").atZone(ZoneId.systemDefault())))
                        .value()
        );
        assertEquals("true",
                Auth0Utils.toCognitoAttribute(schema,
                        AttributeBuilder.build("bool", Boolean.TRUE))
                        .value()
        );

        // No schema case
        assertThrows(InvalidAttributeValueException.class,
                () -> Auth0Utils.toCognitoAttribute(schema,
                        AttributeBuilder.build("foo", "test"))
                        .value()
        );
    }

    @Test
    void toCognitoAttributeForDelete() {
        AttributeType attributeType = Auth0Utils.toCognitoAttributeForDelete(
                AttributeBuilder.build("foo", "test"));
        assertEquals("foo", attributeType.name());
        assertEquals("", attributeType.value());
    }

    @Test
    void checkCognitoResult() {
        SdkHttpResponse sdkHttpResponse = SdkHttpResponse.builder()
                .statusCode(400)
                .build();
        ListUsersResponse.Builder builder = ListUsersResponse.builder();
        builder.sdkHttpResponse(sdkHttpResponse);
        ListUsersResponse response = builder.build();

        assertThrows(ConnectorException.class,
                () -> Auth0Utils.checkCognitoResult(response, "ListUsers"));
    }

    @Test
    void shouldReturnPartialAttributeValues() {
        OperationOptions noOptions = new OperationOptionsBuilder().build();
        assertFalse(Auth0Utils.shouldAllowPartialAttributeValues(noOptions));

        OperationOptions falseOption = new OperationOptionsBuilder().setAllowPartialAttributeValues(false).build();
        assertFalse(Auth0Utils.shouldAllowPartialAttributeValues(falseOption));

        OperationOptions trueOption = new OperationOptionsBuilder().setAllowPartialAttributeValues(true).build();
        assertTrue(Auth0Utils.shouldAllowPartialAttributeValues(trueOption));
    }
}