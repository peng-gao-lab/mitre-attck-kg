#! python3
import sys, logging, random, datetime

sys.path.append("..")
from configs import *
from py2neo.ogm import Model, Property, RelatedTo, RelatedFrom

# Setting
# logging.basicConfig(level=logging.DEBUG)

def getData(name, entity, isDate=False):
    res = entity.get(name, None)
    if isDate:
        # TODO
        pass
    if res:
        if type(res) == str:
            res = res.replace('"', '*')
        elif type(res) == list and len(res) != 0:
            for i in range(len(res)):
                res[i] = res[i].replace('"', '*')
        elif type(res) == bool:
            pass
        elif isinstance(res, datetime.datetime):
            res = res.date()
        else:
            res = str(res)
    return res


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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.revoked = getData("revoked", entity)
        self.identity_class = getData("identity_class", entity)
        return True

    def add_relations(self, graph, entity):
        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                if md != None:
                    self.marker.add(md)
        return []


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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.difinition_type = getData("difinition_type", entity)
        self.definition = getData("definition", entity)
        return True

    def add_relations(self, graph, entity):
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
        return []


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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.revoked = getData("revoked", entity)
        self.x_mitre_data_sources = getData("x_mitre_data_sources", entity)
        self.x_mitre_detection = getData("x_mitre_detection", entity)
        self.x_mitre_is_subtechnique = getData("x_mitre_is_subtechnique", entity)
        self.x_mitre_platforms = getData("x_mitre_platforms", entity)
        self.x_mitre_contributors = getData("x_mitre_contributors", entity)
        self.x_mitre_impact_type = getData("x_mitre_impact_type", entity)
        self.x_mitre_effective_permissions = getData("x_mitre_effective_permissions", entity)
        self.x_mitre_system_requirements = getData("x_mitre_system_requirements", entity)
        self.x_mitre_defense_bypassed = getData("x_mitre_defense_bypassed", entity)
        self.x_mitre_network_requirements = getData("x_mitre_network_requirements", entity)
        self.x_mitre_remote_support = getData("x_mitre_remote_support", entity)
        self.x_mitre_deprecated = getData("x_mitre_deprecated", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        kcps = entity.get("kill_chain_phases")
        for kcp in kcps:
            node = KillChainPhase()
            node.add_properties(kcp)
            self.owned_kcp.add(node)
            nodes.append(node)

        return nodes


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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.revoked = getData("revoked", entity)
        self.x_mitre_platforms = getData("x_mitre_platforms", entity)
        self.x_mitre_contributors = getData("x_mitre_contributors", entity)
        self.x_mitre_deprecated = getData("x_mitre_deprecated", entity)
        self.x_mitre_old_attack_id = getData("x_mitre_old_attack_id", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes

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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.revoked = getData("revoked", entity)
        self.x_mitre_deprecated = getData("x_mitre_deprecated", entity)
        self.x_mitre_old_attack_id = getData("x_mitre_old_attack_id", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes



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

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.revoked = getData("revoked", entity)
        self.x_mitre_contributors = getData("x_mitre_contributors", entity)
        self.x_mitre_deprecated = getData("x_mitre_deprecated", entity)
        self.aliases = getData("aliases", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes

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
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.x_mitre_shortname = getData("x_mitre_shortname", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes


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
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        refs = getData("tactic_refs", entity)
        if refs:
            for ref in refs:
                tac = Tactic.match(graph, ref).first()
                self.listed.add(tac)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes


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
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    owned_er = RelatedTo("ExternalReference", "OWN")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        self.x_mitre_platforms = getData("x_mitre_platforms", entity)
        self.x_mitre_collection_layers = getData("x_mitre_collection_layers", entity)
        return True

    def add_relations(self, graph, entity):
        nodes = []
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ers = entity.get("external_references")
        for er in ers:
            node = ExternalReference()
            node.add_properties(er)
            self.owned_er.add(node)
            nodes.append(node)

        return nodes

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
    source = RelatedTo("DataSource", "REF")
    detected = RelatedTo("Technique", "DETECT")
    creator = RelatedTo("Identity", "CREATED_BY")
    marker = RelatedTo("MarkingDefinition", "MARKED_BY")
    modifier = RelatedTo("Identity", "MODIFIED_BY")

    def add_properties(self, entity):
        self.id = getData("id", entity)
        self.name = getData("name", entity)
        self.types = getData("type", entity)
        self.spec_version = getData("spec_version", entity)
        self.x_mitre_version = getData("x_mitre_version", entity)
        self.x_mitre_attack_spec_version = getData("x_mitre_attack_spec_version", entity)
        self.x_mitre_domains = getData("x_mitre_domains", entity)
        self.created = getData("created", entity)
        self.modified = getData("modified", entity)
        self.description = getData("description", entity)
        return True

    def add_relations(self, graph, entity):
        ref = getData("created_by_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            self.creator.add(idt)
            self.modifier.add(idt)

        refs = getData("object_marking_refs", entity)
        if refs:
            for ref in refs:
                md = MarkingDefinition.match(graph, ref).first()
                self.marker.add(md)

        ref = getData("x_mitre_data_source_ref", entity)
        if ref:
            idt = Identity.match(graph, ref).first()
            if idt:
                self.source.add(idt)

        return []

# external_reference
class ExternalReference(Model):
    # Properties
    # __primarykey__ = "url"
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

    def add_properties(self, entity):
        self.external_id = getData("external_id", entity)
        self.url = getData("url", entity)
        # if self.url == None:
            # logging.error("url null: {}".format(str(entity)))
        self.er_description = getData("er_description", entity)
        self.source_name = getData("source_name", entity)
        return True

# kill_chain_phase
class KillChainPhase(Model):
    # Properties
    kill_chain_name = Property()
    phase_name = Property()

    # Relationships
    owner = RelatedFrom("Technique", "OWN")

    def add_properties(self, entity):
        self.kill_chain_name = getData("kill_chain_name", entity)
        self.phase_name = getData("phase_name", entity)
        return True

def parseRelationship(relation):
    sid = relation.get("source_ref")
    tid = relation.get("target_ref")
    if not sid or not tid:
        logging.error("Parsing relation error: {}".format(relation))
        return
    stype = sid.split("--")[0]
    ttype = tid.split("--")[0]
    rtype = relation.get("relationship_type")

    stype = stixToAttackTerm[stype]
    ttype = stixToAttackTerm[ttype]
    rtype = RELATION_TYPE_TRANSFORM[rtype]
    return stype, sid, ttype, tid, rtype

'''
course-of-action	=>	mitigates	=>	attack-pattern

intrusion-set	=>	uses	=>	malware

intrusion-set	=>	uses	=>	attack-pattern

malware	=>	uses	=>	attack-pattern

intrusion-set	=>	uses	=>	tool

tool	=>	uses	=>	attack-pattern

malware	=>	revoked-by	=>	malware

intrusion-set	=>	revoked-by	=>	intrusion-set

attack-pattern	=>	subtechnique-of	=>	attack-pattern

attack-pattern	=>	revoked-by	=>	attack-pattern

x-mitre-data-component	=>	detects	=>	attack-pattern
'''
# Add external relationships, which are defined by relationship entity
def addRelat(graph, relat):
    stype, sid, ttype, tid, rtype = parseRelationship(relat)
    if stype == "mitigation" and ttype == "technique":
        mit = Mitigation.match(graph, sid).first()
        tech = Technique.match(graph, tid).first()
        if mit and tech:
            mit.mitigated.add(tech)
        return [mit, tech]
    if stype == "groups" and ttype == "software":
        grp = Group.match(graph, sid).first()
        sw = Software.match(graph, tid).first()
        if grp and sw:
            grp.used_sw.add(sw)
        return [grp, sw]
    if stype == "groups" and ttype == "technique":
        grp = Group.match(graph, sid).first()
        tech = Technique.match(graph, tid).first()
        if grp and tech:
            grp.used_tech.add(tech)
        return [grp, tech]
    if stype == "software" and ttype == "technique":
        sw = Software.match(graph, sid).first()
        tech = Technique.match(graph, tid).first()
        if sw and tech:
            sw.used.add(tech)
        return [sw, tech]
    if stype == "software" and ttype == "software":
        sw1 = Software.match(graph, sid).first()
        sw2 = Software.match(graph, tid).first()
        if sw1 and sw2:
            sw1.revoker.add(sw2)
        return [sw1, sw2]
    if stype == "groups" and ttype == "groups":
        grp1 = Group.match(graph, sid).first()
        grp2 = Group.match(graph, tid).first()
        if grp1 and grp2:
            grp1.revoker.add(grp2)
        return [grp1, grp2]
    if stype == "technique" and ttype == "technique" and rtype == "revoked-by":
        tech1 = Technique.match(graph, sid).first()
        tech2 = Technique.match(graph, tid).first()
        if tech1 and tech2:
            tech1.revoker.add(tech2)
        return [tech1, tech2]
    if stype == "technique" and ttype == "technique" and rtype == "subtechnique-of":
        tech1 = Technique.match(graph, sid).first()
        tech2 = Technique.match(graph, tid).first()
        if tech1 and tech2:
            tech1.supertech.add(tech2)
        return [tech1, tech2]
    if stype == "data_component" and ttype == "technique":
        dc = DataComponent.match(graph, sid).first()
        tech = Technique.match(graph, tid).first()
        if dc and tech:
            dc.detected.add(tech)
        return [dc, tech]


def test():
    res = []
    logging.info("Test beginning")
    identity = Identity()
    res.append(identity)
    marking_definition = MarkingDefinition()
    res.append(marking_definition)
    technique = Technique()
    res.append(technique)
    tactic = Tactic()
    res.append(tactic)
    matrix = Matrix()
    res.append(matrix)
    group = Group()
    res.append(group)
    software = Software()
    res.append(software)
    mitigation = Mitigation()
    res.append(mitigation)
    data_souce = DataSource()
    res.append(data_souce)
    data_component = DataComponent()
    res.append(data_component)
    for node in res:
        node.id = str(random.randint(1, 1000))
        node.name = 'name' + node.id
    return res


if __name__ == "__main__":
    logging.debug("Begin")
    res = test()
    logging.debug("Succeed")

