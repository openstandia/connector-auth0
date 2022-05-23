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

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

public class Auth0FilterTranslator extends AbstractFilterTranslator<Auth0Filter> {

    private static final Log LOG = Log.getLog(Auth0FilterTranslator.class);

    private final OperationOptions options;
    private final ObjectClass objectClass;

    public Auth0FilterTranslator(ObjectClass objectClass, OperationOptions options) {
        this.objectClass = objectClass;
        this.options = options;
    }

    @Override
    protected Auth0Filter createEqualsExpression(EqualsFilter filter, boolean not) {
        if (not) { // no way (natively) to search for "NotEquals"
            return null;
        }
        Attribute attr = filter.getAttribute();

        if (attr instanceof Uid) {
            Uid uid = (Uid) attr;
            Name nameHint = uid.getNameHint();
            if (nameHint != null) {
                Auth0Filter nameFilter = new Auth0Filter(nameHint.getName(),
                        Auth0Filter.FilterType.EXACT_MATCH,
                        nameHint.getNameValue());
                return nameFilter;
            }
        }

        Auth0Filter auth0Filter = new Auth0Filter(attr.getName(),
                Auth0Filter.FilterType.EXACT_MATCH,
                AttributeUtil.getAsStringValue(attr));

        return auth0Filter;
    }
}
