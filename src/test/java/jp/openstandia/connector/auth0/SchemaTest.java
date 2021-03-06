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
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.Schema;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class SchemaTest extends AbstractTest {

    @Test
    void schema() {
        Schema schema = connector.schema();

        assertNotNull(schema);
        assertEquals(4, schema.getObjectClassInfo().size());

        List<ObjectClassInfo> users = schema.getObjectClassInfo().stream().filter(o -> o.getType().startsWith("User_")).collect(Collectors.toList());
        Optional<ObjectClassInfo> role = schema.getObjectClassInfo().stream().filter(o -> o.is("Role")).findFirst();
        Optional<ObjectClassInfo> organization = schema.getObjectClassInfo().stream().filter(o -> o.is("Organization")).findFirst();

        assertEquals(2, users.size());
        assertTrue(role.isPresent());
        assertTrue(organization.isPresent());
    }
}
