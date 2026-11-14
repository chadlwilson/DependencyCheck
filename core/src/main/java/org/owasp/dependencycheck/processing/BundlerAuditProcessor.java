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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.processing;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.Advisory;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.Gem;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.Report;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.processing.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;

/**
 * Processor for the JSON output of `bundle-audit check --format json`.
 *
 * @author Jeremy Long
 */
public class BundlerAuditProcessor extends Processor<InputStream> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BundlerAuditProcessor.class);
    /**
     * Reference to the gem lock dependency.
     */
    private final Dependency gemDependency;
    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private IOException ioException;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private AnalysisException analysisException;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private CpeValidationException cpeException;

    /**
     * Constructs a new processor to consume the output of `bundler-audit`.
     *
     * @param gemDependency a reference to `gem.lock` dependency
     * @param engine a reference to the dependency-check engine
     */
    public BundlerAuditProcessor(Dependency gemDependency, Engine engine) {
        this.gemDependency = gemDependency;
        this.engine = engine;
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws IOException thrown if an IO Exception occurred
     * @throws AnalysisException thrown if the bundle-audit output could not be
     * parsed
     * @throws CpeValidationException thrown if a CPE validation exception
     * occurred
     */
    @Override
    public void close() throws IOException, AnalysisException, CpeValidationException {
        if (ioException != null) {
            addSuppressedExceptions(ioException, analysisException, cpeException);
            throw ioException;
        }
        if (analysisException != null) {
            addSuppressedExceptions(analysisException, cpeException);
            throw analysisException;
        }
        if (cpeException != null) {
            throw cpeException;
        }
    }

    @Override
    public void run() {
        try (Reader reader = new InputStreamReader(getInput(), StandardCharsets.UTF_8)) {
            processResults(BundleAuditJsonParser.parse(reader));
        } catch (IOException ex) {
            this.ioException = ex;
        } catch (AnalysisException ex) {
            this.analysisException = ex;
        } catch (CpeValidationException ex) {
            this.cpeException = ex;
        }
    }

    /**
     * Creates a dependency for each affected gem and attaches a vulnerability
     * for each advisory reported against it.
     *
     * @param report the parsed bundle-audit report
     * @throws IOException thrown if a dependency could not be created
     * @throws CpeValidationException thrown if the vulnerable software entry
     * could not be built
     */
    private void processResults(Report report) throws IOException, CpeValidationException {
        final String parentName = gemDependency.getActualFile().getParentFile().getName();
        final Map<String, Dependency> dependencies = new HashMap<>();
        for (BundleAuditJsonParser.GemResult result : report.getUnpatchedGems()) {
            final Gem gem = result.getGem();
            final Advisory advisory = result.getAdvisory();
            LOGGER.debug("bundle-audit ({}): {} {} {}", parentName, gem.getName(), gem.getVersion(), advisory.getId());
            dependencies.computeIfAbsent(gem.getName(), k -> createDependencyForGem(parentName, gem))
                    .addVulnerability(createVulnerability(gem, advisory));
        }
    }

    /**
     * Creates a vulnerability from a bundle-audit advisory.
     *
     * @param gem the affected gem
     * @param advisory the advisory
     * @return the vulnerability
     * @throws CpeValidationException thrown if there is an error building the
     * vulnerable software entry
     */
    private Vulnerability createVulnerability(Gem gem, Advisory advisory) throws CpeValidationException {
        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.BUNDLEAUDIT);
        final String name = determineName(advisory);
        vulnerability.setName(name);
        vulnerability.setDescription(buildDescription(advisory));
        if (advisory.getUrl() != null) {
            vulnerability.addReference(Advisory.SOURCE, name, advisory.getUrl());
        }
        addAlternateIdentifiers(vulnerability, advisory, name);
        addCvssData(vulnerability, advisory);

        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                .vendor(gem.getName())
                .product(String.format("%s_project", gem.getName()))
                .version(gem.getVersion()).build();
        vulnerability.addVulnerableSoftware(vs);
        vulnerability.setMatchedVulnerableSoftware(vs);
        return vulnerability;
    }

    /**
     * Attaches the identifiers that were not selected as the canonical name
     * (see {@link #determineName(Advisory)}) as references so that they remain
     * visible in the report.
     *
     * @param vulnerability the vulnerability
     * @param advisory the advisory
     * @param name the canonical name of the vulnerability
     */
    private static void addAlternateIdentifiers(Vulnerability vulnerability, Advisory advisory, String name) {
        final String ghsaId = advisory.getGhsaId();
        if (ghsaId != null && !ghsaId.equals(name)) {
            vulnerability.addReference(Advisory.SOURCE, ghsaId, advisory.getGhsaUrl());
        }
        final String osvdbId = advisory.getOsvdbId();
        if (osvdbId != null && !osvdbId.equals(name)) {
            //OSVDB is defunct - there is no URL to link to
            vulnerability.addReference(Advisory.SOURCE, osvdbId, null);
        }
    }

    /**
     * Determines the name of the vulnerability: the CVE identifier when one
     * exists, otherwise the GHSA identifier, otherwise the legacy OSVDB
     * identifier, falling back to the advisory identifier from the
     * ruby-advisory-db.
     *
     * @param advisory the advisory
     * @return the vulnerability name
     */
    private static String determineName(Advisory advisory) {
        if (advisory.getCveId() != null) {
            return advisory.getCveId();
        }
        if (advisory.getGhsaId() != null) {
            return advisory.getGhsaId();
        }
        if (advisory.getOsvdbId() != null) {
            return advisory.getOsvdbId();
        }
        return advisory.getId();
    }

    /**
     * Builds the vulnerability description from the advisory title,
     * description and version information.
     *
     * @param advisory the advisory
     * @return the description
     */
    private static String buildDescription(Advisory advisory) {
        final StringBuilder sb = new StringBuilder();
        if (advisory.getTitle() != null) {
            sb.append(advisory.getTitle().trim()).append("\n\n");
        }
        if (advisory.getDescription() != null) {
            sb.append(advisory.getDescription().trim());
        }
        if (!advisory.getPatchedVersions().isEmpty()) {
            sb.append("\n\nPatched versions: ").append(String.join(", ", advisory.getPatchedVersions()));
        }
        if (!advisory.getUnaffectedVersions().isEmpty()) {
            sb.append("\n\nUnaffected versions: ").append(String.join(", ", advisory.getUnaffectedVersions()));
        }
        return sb.toString();
    }

    /**
     * Adds CVSS data to the vulnerability. The NVD data is used when the
     * advisory has a CVE identifier that is known to dependency-check;
     * otherwise the CVSSv4, CVSSv3 and CVSSv2 base scores recorded in the
     * ruby-advisory-db are used (bundler-audit 0.9.3 does not emit CVSSv4). If
     * no score is available the bundle-audit criticality is recorded as the
     * unscored severity.
     *
     * @param vulnerability the vulnerability
     * @param advisory the advisory
     */
    private void addCvssData(Vulnerability vulnerability, Advisory advisory) {
        final Vulnerability nvd = lookupNvdVulnerability(advisory.getCveId());
        if (nvd != null && (nvd.getCvssV2() != null || nvd.getCvssV3() != null || nvd.getCvssV4() != null)) {
            if (nvd.getCvssV2() != null) {
                vulnerability.setCvssV2(nvd.getCvssV2());
            }
            if (nvd.getCvssV3() != null) {
                vulnerability.setCvssV3(nvd.getCvssV3());
            }
            if (nvd.getCvssV4() != null) {
                vulnerability.setCvssV4(nvd.getCvssV4());
            }
            return;
        }
        final AtomicBoolean scored = new AtomicBoolean(false);
        advisory.toCvssV4().ifPresent(score -> {
            vulnerability.setCvssV4(score);
            scored.set(true);
        });
        advisory.toCvssV3().ifPresent(score -> {
            vulnerability.setCvssV3(score);
            scored.set(true);
        });
        advisory.toCvssV2().ifPresent(score -> {
            vulnerability.setCvssV2(score);
            scored.set(true);
        });
        if (!scored.get()) {
            LOGGER.debug("bundle-audit vulnerability missing CVSS data: {}", vulnerability.getName());
            final String criticality = advisory.getCriticality();
            vulnerability.setUnscoredSeverity(criticality == null ? "UNKNOWN" : criticality.toUpperCase(Locale.ROOT));
        }
    }

    /**
     * Looks up the vulnerability in the NVD data.
     *
     * @param cveId the CVE identifier; may be null
     * @return the NVD vulnerability, or null if it is not available
     */
    private Vulnerability lookupNvdVulnerability(String cveId) {
        if (cveId == null) {
            return null;
        }
        final CveDB cvedb = engine.getDatabase();
        if (cvedb == null) {
            return null;
        }
        try {
            return cvedb.getVulnerability(cveId);
        } catch (DatabaseException ex) {
            LOGGER.debug("Unable to look up vulnerability {}", cveId, ex);
            return null;
        }
    }

    /**
     * Creates the dependency for an affected gem and adds it to the engine.
     *
     * @param parentName the name of the directory containing the Gemfile.lock
     * @param affected the affected gem
     * @return the dependency
     */
    private Dependency createDependencyForGem(String parentName, Gem affected) {
        final String gem = affected.getName();
        final String version = affected.getVersion();
        final File gemFile = gemDependency.getActualFile();
        final String fileName = gemDependency.getFileName();
        final String displayFileName = String.format("%s%c%s:%s", parentName, File.separatorChar, fileName, gem);
        final Dependency dependency = new Dependency(gemFile, true);
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dependency.setName(gem);
        dependency.setVersion(version);
        dependency.addEvidence(EvidenceType.PRODUCT, "bundler-audit", "Name", gem, Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VENDOR, "bundler-audit", "Name", gem, Confidence.HIGH);
        dependency.addEvidence(EvidenceType.VERSION, "bundler-audit", "Version", version, Confidence.HIGHEST);
        try {
            final PackageURL purl = PackageURLBuilder.aPackageURL().withType("gem").withName(gem)
                    .withVersion(version).build();
            dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for gem", ex);
            dependency.addSoftwareIdentifier(new GenericIdentifier("gem:" + gem + "@" + version, Confidence.HIGHEST));
        }
        dependency.setDisplayFileName(displayFileName);
        dependency.setFileName(fileName);
        dependency.setFilePath(gemDependency.getFilePath());
        //sha1sum is used for anchor links in the HTML report
        dependency.setSha1sum(Checksum.getSHA1Checksum(displayFileName));
        engine.addDependency(dependency);
        return dependency;
    }
}
