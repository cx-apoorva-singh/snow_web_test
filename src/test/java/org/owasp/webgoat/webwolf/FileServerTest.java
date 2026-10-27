/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.webwolf.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(FileServer.class)
@Import(WebSecurityConfig.class)
class FileServerTest {

  @TempDir static Path root;

  @Autowired private MockMvc mvc;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockitoBean private UserService userService;

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry registry) {
    registry.add("webwolf.fileserver.location", () -> root.resolve("fileserver").toString());
    registry.add("server.address", () -> "localhost");
    registry.add("server.servlet.context-path", () -> "/WebWolf");
    registry.add("server.port", () -> "9090");
  }

  @Test
  @WithMockUser(username = "alice")
  void uploadStoresFileInUserFolder() throws Exception {
    mvc.perform(multipart("/fileupload").file(file("hello.txt")))
        .andExpect(status().is3xxRedirection());

    assertThat(root.resolve("fileserver").resolve("alice").resolve("hello.txt")).exists();
  }

  @ParameterizedTest
  @ValueSource(strings = {"../evil.txt", "../../evil.txt", "sub/../../evil.txt"})
  @WithMockUser(username = "alice")
  void traversalSegmentsAreStrippedToUserFolder(String name) throws Exception {
    mvc.perform(multipart("/fileupload").file(file(name))).andExpect(status().is3xxRedirection());

    assertThat(root.resolve("fileserver").resolve("alice").resolve("evil.txt")).exists();
    assertNoEvilFileOutsideUserFolder();
  }

  @Test
  @WithMockUser(username = "alice")
  void absolutePathIsStoredInUserFolder() throws Exception {
    Path outside = root.resolve("absolute-evil.txt");
    mvc.perform(multipart("/fileupload").file(file(outside.toString())))
        .andExpect(status().is3xxRedirection());

    assertThat(outside).doesNotExist();
    assertThat(root.resolve("fileserver").resolve("alice").resolve("absolute-evil.txt")).exists();
  }

  @ParameterizedTest
  @ValueSource(strings = {"..", ".", "../", "foo/..", "", " "})
  @WithMockUser(username = "alice")
  void invalidNamesAreRejected(String name) throws Exception {
    mvc.perform(multipart("/fileupload").file(file(name))).andExpect(status().isBadRequest());
  }

  private static MockMultipartFile file(String name) {
    return new MockMultipartFile("file", name, "text/plain", "content".getBytes());
  }

  private static void assertNoEvilFileOutsideUserFolder() throws IOException {
    Path userDir = root.resolve("fileserver").resolve("alice");
    try (Stream<Path> files = Files.walk(root)) {
      assertThat(
              files.filter(p -> p.getFileName().toString().equals("evil.txt"))
                  .filter(p -> !p.getParent().equals(userDir)))
          .isEmpty();
    }
  }
}
