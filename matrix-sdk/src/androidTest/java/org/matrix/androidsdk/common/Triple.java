/*
 * Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matrix.androidsdk.common;

import android.util.Pair;

public class Triple<A, B, C> {
    public A first;
    public B second;
    public C third;

    /**
     * Constructor for a Triple.
     *
     * @param first  the first object in the Triple
     * @param second the second object in the Triple
     * @param third  the third object in the Triple
     */
    public Triple(A first, B second, C third) {
        this.first = first;
        this.second = second;
        this.third = third;
    }

    /**
     * Constructor from a Pair and another element
     *
     * @param pair
     * @param third
     */
    public Triple(Pair<A, B> pair, C third) {
        this(pair.first, pair.second, third);
    }
}
