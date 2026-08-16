## Description
<!-- Provide a clear and concise summary of the changes introduced by this PR. -->
<!-- Example: Implemented the Azure Function in Python to parse the Sentinel webhook and extract the IPAddress and TargetVM properties. -->


## Requirement Addressed
<!-- Link to the specific functional requirement or issue this PR resolves. -->
- **REQ-ID:** <!-- e.g., REQ-3.2.1, REQ-3.6.5 -->

## Type of Change
<!-- Check the appropriate box using an 'x' [x] -->
- [ ] ☁️ **Infrastructure** (Bicep/ARM templates, networking, IAM roles)
- [ ] 🐍 **Backend/Serverless** (Python Azure Functions, API logic)
- [ ] 🗄️ **Database/Storage** (SQL schema updates, Cosmos DB queries, Blob storage)
- [ ] 🐋 **Containers/Analysis** (Dockerfile, SIFT/Plaso shell scripts)
- [ ] 🎨 **Reporting/UI** (HTML/CSS layout for the PDF generation)
- [ ] 📝 **Documentation** (README updates, architecture diagrams)

## Testing Performed
<!-- Describe how you tested these changes locally or in your test environment. -->
<!-- Example 1: Ran the Python unit tests via Pytest, verifying the NSG swap logic accurately authenticates and targets the correct NIC. -->
<!-- Example 2: Deployed the SQL ledger schema locally and successfully executed an INSERT statement containing a dummy SHA-256 hash. -->
<!-- Example 3: Rendered the HTML template with dummy data to ensure the CSS aligns the colored threat-level boxes and timeline tables correctly before the PDF conversion. -->


## Reviewer Instructions
<!-- Point out specific files, logic, or cloud computing boundaries the reviewer should focus on. -->
- Focus on `src/functions/NetworkContainment/__init__.py`. Pay special attention to how the Azure identity credential handles the subscription ID parsing.

## Deployment / Rollback Risks
<!-- Are there any breaking changes? Does the cloud infrastructure need to be destroyed and recreated? -->
- [ ] No perceived risk.
- [ ] **Requires attention:** <!-- e.g., The Cosmos DB partition key was changed; old data must be migrated. -->

## Checklist
- [ ] My code strictly adheres to the assigned directory boundaries.
- [ ] The CI/CD Pipeline (GitHub Actions) is passing.
- [ ] I have removed all hardcoded secrets or local connection strings.
- [ ] I have performed a self-review of my own code before opening this PR.