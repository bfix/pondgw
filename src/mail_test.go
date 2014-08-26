/*
 * Unit tests for methods related to user handling.
 *
 * (c) 2014 Bernd Fix   >Y<
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

///////////////////////////////////////////////////////////////////////
// Import external declarations.

import (
	"fmt"
	"testing"
)

///////////////////////////////////////////////////////////////////////
// Unit test functions

//=====================================================================
// Validation tests
//=====================================================================

/*
 * Check email addresses
 * (see https://en.wikipedia.org/wiki/Email_address#Examples)
 */
func TestEMailValidator(t *testing.T) {

	var data = [][]string{
		{"+", "niceandsimple@example.com"},
		{"+", "very.common@example.com"},
		{"+", "a.little.lengthy.but.fine@dept.example.com"},
		{"+", "disposable.style.email.with+symbol@example.com"},
		{"+", "other.email-with-dash@example.com"},
		{"+", "user@localserver"},
		{"+", "peg-test+7qjTsnM4VBYAut4hStvWTuoPwXFSvPxD2ZLfa8kFjXA1@hoi-polloi.org"},
		{"-", "Abc.example.com"},
		{"-", "A@b@c@example.com"},
		{"-", "a\"b(c)d,e:f;g<h>i[j\\k]l@example.com"},
		{"-", "john..doe@example.com"},
		{"-", "john.doe@example..com"},
	}

	for _, d := range data {
		rc := IsValidEmailAddress(d[1])
		if !rc && d[0] == "+" {
			t.Error("Test for address '" + d[1] + "' failed.")
		}
		if rc && d[0] == "-" {
			t.Error("Test for address '" + d[1] + "' should fail, but didn't.")
		}
		sub := GetSubAddress(d[1])
		if len(sub) > 0 {
			fmt.Printf("SubAddress '%s' from '%s'\n", sub, d[1])
		}
	}
}
