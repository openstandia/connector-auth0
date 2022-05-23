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
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static jp.openstandia.connector.auth0.testutil.MockClient.userExistsError;
import static org.junit.jupiter.api.Assertions.*;

class UserCreateTest extends AbstractTest {

    @Test
    void createUser() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String email = "foo@example.com";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(email));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));

        mockClient.createUser = ((user) -> {
            user.setId(userId);
            return user;
        });

        // When
        Uid uid = connector.create(DEFAULT_USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals(userId, uid.getUidValue());
        assertEquals(email, uid.getNameHintValue());
    }

    @Test
    void createUserWithFullAttrs() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String email = "foo@example.com";
        String nickname = "foo";
        String phoneNumber = "+817000000000";
        String givenName = "Foo";
        String familyName = "Bar";
        String name = "Foo Bar";
        String picture = "https://picture.example.com/foo";
        String username = "foobar";
        boolean emailVerified = true;
        boolean phoneVerified = true;

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(email));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("nickname", nickname));
        attrs.add(AttributeBuilder.build("phone_number", phoneNumber));
        attrs.add(AttributeBuilder.build("given_name", givenName));
        attrs.add(AttributeBuilder.build("family_name", familyName));
        attrs.add(AttributeBuilder.build("name", name));
        attrs.add(AttributeBuilder.build("picture", picture));
        attrs.add(AttributeBuilder.build("username", username));
        attrs.add(AttributeBuilder.build("email_verified", emailVerified));
        attrs.add(AttributeBuilder.build("phone_verified", phoneVerified));

        AtomicReference<User> created = new AtomicReference<User>();
        mockClient.createUser = ((user) -> {
            user.setId(userId);
            created.set(user);
            return user;
        });

        // When
        Uid uid = connector.create(DEFAULT_USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals(userId, uid.getUidValue());
        assertEquals(email, uid.getNameHintValue());

        User newUser = created.get();
        assertNotNull(newUser);
        assertEquals(email, newUser.getEmail());
        assertEquals(nickname, newUser.getNickname());
        assertEquals(phoneNumber, newUser.getPhoneNumber());
        assertEquals(givenName, newUser.getGivenName());
        assertEquals(familyName, newUser.getFamilyName());
        assertEquals(name, newUser.getName());
        assertEquals(picture, newUser.getPicture());
        assertEquals(username, newUser.getUsername());
        assertEquals(emailVerified, newUser.isEmailVerified());
        assertEquals(phoneVerified, newUser.isPhoneVerified());
        assertEquals("Username-Password-Authentication", getString(newUser, "connection"));
    }

    @Test
    void createUserWithAlreadyExistsError() {
        // Given
        String email = "foo@example.com";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(email));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));

        mockClient.createUser = ((user) -> {
            throw userExistsError();
        });

        // When
        AlreadyExistsException e = assertThrows(AlreadyExistsException.class, () -> {
            Uid uid = connector.create(DEFAULT_USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        });

        // Then
        assertNotNull(e);
    }

    @Test
    void disableUser() {
        // Given
        String userId = "auth0|61c5cc0078d9e300758160d6";
        String email = "foo@example.com";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(email));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));
        attrs.add(AttributeBuilder.buildEnabled(false));

        AtomicReference<User> created = new AtomicReference<User>();
        mockClient.createUser = ((user) -> {
            user.setId(userId);
            created.set(user);
            return user;
        });

        // When
        Uid uid = connector.create(DEFAULT_USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Then
        assertEquals(userId, uid.getUidValue());

        User newUser = created.get();
        assertNotNull(newUser);
        assertTrue(newUser.isBlocked());
    }
}
