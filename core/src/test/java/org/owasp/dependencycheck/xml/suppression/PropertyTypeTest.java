/*
 * This file is part of dependency-check-core.
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
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.suppression;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class PropertyTypeTest extends BaseTest {

    /**
     * Test of matches method, of class PropertyType.
     */
    @Test
    void testMatches() {
        String text = "Simple";
        assertTrue(new PropertyType("simple").matches(text));
        assertFalse(new PropertyType("simple", false, true).matches(text));
    }

    @Test
    void testMatchesRegex() {
        String text = "Simple";
        assertTrue(new PropertyType("s.*le", true, false).matches(text));
        assertFalse(new PropertyType("s.*le", true, true).matches(text));
    }

    @Test
    void testMatchesRegexRethrowsCompilationIssue() {
        assertThrowsExactly(PatternSyntaxException.class, () -> new PropertyType("(badregex", true, false).matches("anything"));
        assertThrowsExactly(PatternSyntaxException.class, () -> new PropertyType("(badregex", true, true).matches("anything"));
    }
}
