#! python3
import sys, logging

sys.path.append("..")
from configs import *
from py2neo.ogm import Model, Property, RelatedTo, RelatedFrom

# Setting
logging.basicConfig(level=logging.DEBUG)

# Identity
class Identity(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    identity_class = Property()
    revoked = Property()

    # Relationships
    created_md = RelatedFrom("MarkingDefinition", "CREATED_BY")
    created_tac = RelatedFrom("Tactic", "CREATED_BY")
    created_mtx = RelatedFrom("Matrix", "CREATED_BY")
    created_tech = RelatedFrom("Technique", "CREATED_BY")
    created_gp = RelatedFrom("Group", "CREATED_BY")
    created_sw = RelatedFrom("Software", "CREATED_BY")
    created_mtg = RelatedFrom("Mitigation", "CREATED_BY")
    created_ds = RelatedFrom("DataSource", "CREATED_BY")
    created_dc = RelatedFrom("DataComponent", "CREATED_BY")

    x_mitre_modified_md = RelatedFrom("MarkingDefinition", "MODIFIED_BY")
    x_mitre_modified_tac = RelatedFrom("Tactic", "MODIFIED_BY")
    x_mitre_modified_mtx = RelatedFrom("Matrix", "MODIFIED_BY")
    x_mitre_modified_tech = RelatedFrom("Technique", "MODIFIED_BY")
    x_mitre_modified_gp = RelatedFrom("Group", "MODIFIED_BY")
    x_mitre_modified_sw = RelatedFrom("Software", "MODIFIED_BY")
    x_mitre_modified_mtg = RelatedFrom("Mitigation", "MODIFIED_BY")
    x_mitre_modified_ds = RelatedFrom("DataSource", "MODIFIED_BY")
    x_mitre_modified_dc = RelatedFrom("DataComponent", "MODIFIED_BY")

    marker = RelatedTo("MarkingDefinition", "MARKED_BY")

# marking-definition
class MarkingDefinition(Model):
    __primarykey__ = "id"
    id = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_domains = Property(default=[])
    created = Property()
    definition_type = Property()
    definition = Property()

    # Relationships
    object_marking_md = RelatedFrom("Identity", "MARKED_BY")
    object_marking_tac = RelatedFrom("Tactic", "MARKED_BY")
    object_marking_mtx = RelatedFrom("Matrix", "MARKED_BY")
    object_marking_tech = RelatedFrom("Technique", "MARKED_BY")
    object_marking_gp = RelatedFrom("Group", "MARKED_BY")
    object_marking_sw = RelatedFrom("Software", "MARKED_BY")
    object_marking_mtg = RelatedFrom("Mitigation", "MARKED_BY")
    object_marking_ds = RelatedFrom("DataSource", "MARKED_BY")
    object_marking_dc = RelatedFrom("DataComponent", "MARKED_BY")

    creator = RelatedTo("Identity", "CREATED_BY")


# technique
class Technique(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    revoked = Property()
    x_mitre_data_sources = Property(default=[])
    x_mitre_detection = Property()
    x_mitre_is_subtechnique = Property()
    x_mitre_platforms = Property(default=[])
    x_mitre_contributors = Property(default=[])
    x_mitre_impact_type = Property()
    x_mitre_effective_permissions = Property(default=[])
    x_mitre_permissions_required = Property(default=[])
    x_mitre_system_requirements = Property(default=[])
    x_mitre_defense_bypassed = Property()
    x_mitre_network_requirements = Property(default=[])
    x_mitre_remote_support = Property()
    x_mitre_deprecated = Property()

    # Relationships
    user_sw = RelatedFrom("Software", "USE")
    user_gp = RelatedFrom("Group", "USE")
    revoked = RelatedFrom("Technique", "REVOKED_BY")
    mitigator = RelatedFrom("Mitigation", "MITIGATE")
    subtech = RelatedFrom("Technique", "SUBTECHNIQUE_OF")
    detector = RelatedFrom("DataComponent", "DETECT")

    creator = RelatedTo("Identity", "CREATED_BY")
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    modifier = RelatedTo("Identity", "MODIFIED_BY")
    revoker = RelatedTo("Technique", "REVOKED_BY")
    supertech = RelatedTo("Technique", "SUBTECHNIQUE_OF")
    owned_er = RelatedTo("ExternalReference", "OWN")
    owned_kcp = RelatedTo("KillChainPhase", "OWN")


# Software
class Software(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    revoked = Property()
    x_mitre_platforms = Property(default=[])
    x_mitre_contributors = Property(default=[])
    x_mitre_deprecated = Property()
    x_mitre_old_attack_id = Property()

    # Relationships
    user = RelatedFrom("Group", "USE")
    revoked = RelatedFrom("Software", "REVOKED_BY")

    revoker = RelatedTo("Software", "REVOKED_BY")
    used = RelatedTo("Technique", "USE")
    creator = RelatedTo("Identity", "CREATED_BY")
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    modifier = RelatedTo("Identity", "MODIFIED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")

# mitigation
class Mitigation(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    revoked = Property()
    x_mitre_deprecated = Property()
    x_mitre_old_attack_id = Property()

    # Relationships
    mitigated = RelatedTo("Technique", "MITIGATE")
    creator = RelatedTo("Identity", "CREATED_BY")
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    modifier = RelatedTo("Identity", "MODIFIED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")


# group
class Group(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    aliases = Property(default=[])
    revoked = Property()
    x_mitre_contributors = Property(default=[])
    x_mitre_deprecated = Property()

    # Relationships
    revoked = RelatedFrom("Group", "REVOKED_BY")

    revoker = RelatedTo("Group", "REVOKED_BY")
    used_tech = RelatedTo("Technique", "USE")
    used_sw = RelatedTo("Software", "USE")
    creator = RelatedTo("Identity", "CREATED_BY")
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    modifier = RelatedTo("Identity", "MODIFIED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")

# tactic
class Tactic(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    x_mitre_shortname = Property()

    # Relationships
    owner = RelatedFrom("Matrix", "LIST")

    creator = RelatedTo("Identity", "CREATED_BY")
    marked = RelatedTo("MarkingDefinition", "MARKED")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

# matrix
class Matrix(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()

    # Relationships
    listed = RelatedTo("Tactic", "LIST")
    creator = RelatedTo("Identity", "CREATED_BY")
    marked = RelatedTo("MarkingDefinition", "MARKED")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

# data_source
class DataSource(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()
    x_mitre_platforms = Property(default=[])
    x_mitre_contributors = Property(default=[])
    x_mitre_collection_layers = Property(default=[])

    # Relationships
    component = RelatedFrom("DataComponent", "REF")

    creator = RelatedTo("Identity", "CREATED_BY")
    marked = RelatedTo("MarkingDefinition", "MARKED")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")


# data_component
class DataComponent(Model):
    # Common properties
    __primarykey__ = "id"
    id = Property()
    name = Property()
    types = Property()
    spec_version = Property(default="2.1")
    x_mitre_version = Property(default="10.0")
    x_mitre_attack_spec_version = Property(default="2.1.0")
    x_mitre_domains = Property(default=[])
    created = Property()
    modified = Property()
    # Specific properties
    description = Property()

    # Relationships
    source = RelatedFrom("DataSource", "REF")

    detected = RelatedTo("Technique", "DETECT")
    creator = RelatedTo("Identity", "CREATED_BY")
    marked = RelatedTo("MarkingDefinition", "MARKED")
    modifier = RelatedTo("Identity", "MODIFIED_BY")


# external_reference
class ExternalReference(Model):
    # Properties
    __primarykey__ = "external_id"
    external_id = Property()
    url = Property()
    er_description = Property()
    source_name = Property()

    # Relationships
    owner_tac = RelatedFrom("Tactic", "OWN")
    owner_mtx = RelatedFrom("Matrix", "OWN")
    owner_tech = RelatedFrom("Technique", "OWN")
    owner_gp = RelatedFrom("Group", "OWN")
    owner_sw = RelatedFrom("Software", "OWN")
    owner_mtg = RelatedFrom("Mitigation", "OWN")
    owner_ds = RelatedFrom("DataSource", "OWN")


# kill_chain_phase
class KillChainPhase(Model):
    # Properties
    kill_chain_name = Property()
    phase_name = Property()

    # Relationships
    owner = RelatedFrom("Technique", "OWN")



def test():
    logging.debug("Test beginning")
    identity = Identity()
    marking_definition = MarkingDefinition()
    technique = Technique()
    tactic = Tactic()
    matrix = Matrix()
    group = Group()
    software = Software()
    mitigation = Mitigation()
    data_souce = DataSource()
    data_component = DataComponent()
    return True


if __name__ == "__main__":
    logging.debug("Begin")
    test()
    logging.debug("Succeed")

