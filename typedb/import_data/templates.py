#! python3
# *_template functions definition
import sys, logging
sys.path.append("../..")
from configs import *

# Setting
logging.basicConfig(level=logging.DEBUG)

##############################################
########### Add entities templates############
##############################################

# Add string properties
def addStr(entity, ppt):
    p = entity.get(ppt, None)
    if p:
        return ', has ' + ppt + ' "' + p.replace('"', '*') + '"'
    else:
        return ''

# Add date properties
def addDate(entity, ppt):
    p = entity.get(ppt, None)
    if p and type(p) != str:
        return ', has ' + ppt + ' ' + p.isoformat()[:19]
    else:
        return ''

# Add boolean
def addBool(entity, ppt):
    p = entity.get(ppt, None)
    if p:
        return ', has ' + ppt + ' ' + str(p).lower()
    else:
        return ''

# Add List properties
def addList(entity, ppts):
    res = ''
    ppt = entity.get(ppts, None)
    if not ppt:
        return ''
    for p in ppt:
        res += ', has ' + ppts + ' "' + p.replace('"', '*') +'"'
    return res

def addCommonPpts(entity):
    temp = ''
    temp += addStr(entity, "types")
    temp += addStr(entity, "name")
    temp += addStr(entity, "spec_version")
    temp += addDate(entity, "created")
    temp += addDate(entity, "modified")
    temp += addStr(entity, "x_mitre_version")
    temp += addList(entity, "x_mitre_domains")
    temp += addStr(entity, "x_mitre_attack_spec_version")
    return temp


'''
    "identity": [
        "type",
        "spec_version",
        "id",
        "created",
        "modified",
        "name",
        "identity_class",
        "revoked",
        "object_marking_refs",
        "x_mitre_domains",
        "x_mitre_attack_spec_version",
        "x_mitre_version"
    ],
    type => types
'''
def identity_template(identity):
    temp = ' $identity isa identity, has id "' + identity["id"] + '"'
    temp += addCommonPpts(identity)
    temp += addBool(identity, "revoked")
    temp += addStr(identity, "identity_class")
    temp += ';'
    return [], [temp]


'''
    "marking-definition": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "definition_type",
        "definition",
        "x_mitre_domains"
    ]
    type => types
'''
def marking_definition_template(marking_definition):
    temp = ' $marking-definition isa marking-definition, has id "' + marking_definition["id"] + '"'
    temp += addStr(marking_definition, "types")
    temp += addStr(marking_definition, "spec_version")
    temp += addDate(marking_definition, "created")
    temp += addStr(marking_definition, "definition_type")
    temp += ', has definition "' + marking_definition["definition_type"] + \
        marking_definition["definition"][marking_definition["definition_type"]] + '"'
    temp += addList(marking_definition, "x_mitre_domains")
    temp += ';'

    matches = []
    inserts = []
    inserts.append(temp)

    # Add created_by_ref relation
    created_by_ref = marking_definition.get("created_by_ref")
    if not created_by_ref:
        logging.error("{} does not have created_by_ref property".format(marking_definition))
    else:
        tmp_match, tmp_insert = created_by_ref_template("marking-definition", created_by_ref)
        matches.append(tmp_match)
        inserts.append(tmp_insert)
    return matches, inserts

'''
    "attack-pattern": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "kill_chain_phases",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_data_sources",
        "x_mitre_detection",
        "x_mitre_domains",
        "x_mitre_is_subtechnique",
        "x_mitre_modified_by_ref",
        "x_mitre_permissions_required",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_system_requirements",
        "x_mitre_defense_bypassed",
        "x_mitre_effective_permissions",
        "x_mitre_impact_type",
        "x_mitre_network_requirements",
        "x_mitre_remote_support",
        "x_mitre_attack_spec_version",
        "x_mitre_deprecated"
    ],
    type => types
'''
def technique_template(technique):
    # Common properties
    temp = ' $technique isa technique, has id "' + technique["id"] + '"'
    temp += addCommonPpts(technique)

    # Particular properties
    temp += addBool(technique, "revoked")
    temp += addStr(technique, "description")
    temp += addList(technique, "x_mitre_data_sources")
    temp += addStr(technique, "x_mitre_detection")
    temp += addBool(technique, "x_mitre_is_subtechnique")
    temp += addList(technique, "x_mitre_permissions_required")
    temp += addList(technique, "x_mitre_platforms")
    temp += addList(technique, "x_mitre_contributors")
    temp += addList(technique, "x_mitre_system_requirements")
    temp += addList(technique, "x_mitre_defense_bypassed")
    temp += addList(technique, "x_mitre_effective_permissions")
    temp += addList(technique, "x_mitre_impact_type")
    temp += addBool(technique, "x_mitre_network_requirements")
    temp += addBool(technique, "x_mitre_remote_support")
    temp += addBool(technique, "x_mitre_deprecated")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = technique.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "technique", count)
        count += 1

    # Add kill_chain_phases
    count = 0
    kill_chain_phases = technique.get("kill_chain_phases")
    for kill_chain_phase in kill_chain_phases:
        temp += kill_chain_phase_template(kill_chain_phase, "technique", count)

    matches = []
    inserts = []
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(technique, "technique")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts

'''
    "malware": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "is_family",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_aliases",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_attack_spec_version",
        "x_mitre_old_attack_id"
    ],
    "tool": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_aliases",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_attack_spec_version",
        "x_mitre_deprecated"
    ],
    type => types
'''
def software_template(software):
    # Common properties
    temp = ' $software isa software, has id "' + software["id"] + '"'
    temp += addCommonPpts(software)

    # Particular properties
    temp += addBool(software, "revoked")
    temp += addStr(software, "description")
    temp += addList(software, "x_mitre_platforms")
    temp += addList(software, "x_mitre_contributors")
    temp += addBool(software, "x_mitre_deprecated")
    temp += addList(software, "x_mitre_aliases")
    temp += addStr(software, "x_mitre_old_attack_id")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = software.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "software", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(software, "software")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts

'''
    "intrusion-set": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "aliases",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_contributors",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version",
        "x_mitre_attack_spec_version",
        "x_mitre_deprecated"
    ],
    type => types
'''
def groups_template(groups):
    # Common properties
    temp = ' $groups isa groups, has id "' + groups["id"] + '"'
    temp += addCommonPpts(groups)

    # Particular properties
    temp += addBool(groups, "revoked")
    temp += addStr(groups, "description")
    temp += addList(groups, "x_mitre_contributors")
    temp += addBool(groups, "x_mitre_deprecated")
    temp += addList(groups, "aliases")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = groups.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "groups", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(groups, "groups")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts


'''
    "course-of-action": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_deprecated",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version",
        "x_mitre_attack_spec_version",
        "x_mitre_old_attack_id"
    ],
    type => types
'''
def mitigation_template(mitigation):
    # Common properties
    temp = ' $mitigation isa mitigation, has id "' + mitigation["id"] + '"'
    temp += addCommonPpts(mitigation)

    # Particular properties
    temp += addBool(mitigation, "revoked")
    temp += addBool(mitigation, "x_mitre_deprecated")
    temp += addStr(mitigation, "x_mitre_old_attack_id")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = mitigation.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "mitigation", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(mitigation, "mitigation")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts


'''
    "x-mitre-tactic": [
        "id",
        "created_by_ref",
        "name",
        "description",
        "external_references",
        "object_marking_refs",
        "x_mitre_shortname",
        "type",
        "modified",
        "created",
        "spec_version",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_attack_spec_version",
        "x_mitre_version"
    ],
    type => types
'''
def tactic_template(tactic):
    # Common properties
    temp = ' $tactic isa tactic, has id "' + tactic["id"] + '"'
    temp += addCommonPpts(tactic)

    # Particular properties
    temp += addStr(tactic, "x_mitre_shortname")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = tactic.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "tactic", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # add common refs
    tmp_matches, tmp_inserts = addCommonRefs(tactic, "tactic")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)
    return matches, inserts


'''
    "x-mitre-matrix": [
        "id",
        "created_by_ref",
        "name",
        "description",
        "external_references",
        "object_marking_refs",
        "type",
        "tactic_refs",
        "modified",
        "created",
        "spec_version",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_attack_spec_version",
        "x_mitre_version"
    ],
    type => types
'''
def matrix_template(matrix):
    # Common properties
    temp = ' $matrix isa matrix, has id "' + matrix["id"] + '"'
    temp += addCommonPpts(matrix)

    # Particular properties
    temp += addStr(matrix, "description")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = matrix.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "matrix", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # Add tactic_refs
    tactic_refs = matrix.get("tactic_refs")
    tmp_matches, tmp_inserts = tactic_refs_template("matrix", tactic_refs[:9])
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(matrix, "matrix")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts

################
## v2.1.0 update
################
'''
    "x-mitre-data-source": {
        "created_by_ref": false,
        "object_marking_refs": false,
        "modified": false,
        "created": false,
        "type": false,
        "id": false,
        "name": false,
        "description": true,
        "x_mitre_platforms": true,
        "x_mitre_collection_layers": true,
        "x_mitre_contributors": true,
        "x_mitre_version": false,
        "external_references": false,
        "spec_version": false,
        "x_mitre_attack_spec_version": false,
        "x_mitre_domains": false,
        "x_mitre_modified_by_ref": false
    },
'''
def data_source_template(data_source):
    # Common properties
    temp = ' $data_source isa data_source, has id "' + data_source["id"] + '"'
    temp += addCommonPpts(data_source)

    # Particular properties
    temp += addStr(data_source, "description")
    temp += addList(data_source, "x_mitre_platforms")
    temp += addList(data_source, "x_mitre_collection_layers")
    temp += addList(data_source, "x_mitre_contributors")
    temp += ';'

    # Add external_reference
    count = 0
    external_references = data_source.get("external_references")
    for external_reference in external_references:
        temp += external_reference_template(external_reference, "data_source", count)
        count += 1

    matches = []
    inserts = []
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(data_source, "data_source")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

    return matches, inserts

'''
    "x-mitre-data-component": {
        "created_by_ref": false,
        "object_marking_refs": false,
        "modified": false,
        "created": false,
        "type": false,
        "id": false,
        "name": false,
        "description": true,
        "x_mitre_version": false,
        "x_mitre_data_source_ref": false,
        "spec_version": false,
        "x_mitre_attack_spec_version": false,
        "x_mitre_domains": false,
        "x_mitre_modified_by_ref": false
    },
'''
def data_component_template(data_component):
    # Common properties
    temp = ' $data_component isa data_component, has id "' + data_component["id"] + '"'
    temp += addCommonPpts(data_component)

    # Particular properties
    temp += addStr(data_component, "description")
    temp += ';'

    matches = []
    inserts = []
    inserts.append(temp)

    # Add x_mitre_data_source_ref
    x_mitre_data_source_ref = data_component.get("x_mitre_data_source_ref")
    match, insert = x_mitre_data_source_ref_template("data_component", x_mitre_data_source_ref)
    inserts.append(insert)
    matches.append(match)

    return matches, inserts


'''
    "external_references": [
        "source_name",
        "url",
        "external_id",
        "description"
    ]

external_references sub relation,
    relates owner,
    relates listed;

This template can only be used as a sub-template,
that means it should be called when inserting other entities.
'''
def external_reference_template(external_reference, owner, count):
    temp = ' $er{} isa external_reference'.format(count)
    temp += addStr(external_reference, "external_id")
    temp += addStr(external_reference, "url")
    temp += addStr(external_reference, "er_description")
    temp += addStr(external_reference, "source_name")
    temp += ';'

    # external_references_template(owner):
    temp += ' $ers{} (listed: $er{}, owner: ${}) isa external_references;'.format(count, count, owner)
    return temp

# fun(listed, owner)


'''
    "kill_chain_phases": [
        "kill_chain_name",
        "phase_name"
    ],

kill_chain_phases sub relation,
    relates owner,
    relates listed;

This template can only be used as a sub-template,
that means it should be called when inserting other entities.
'''
def kill_chain_phase_template(kill_chain_phase, owner, count):
    temp = '$kcp{} isa kill_chain_phase'.format(count)
    temp += addStr(kill_chain_phase, "kill_chain_name")
    temp += addStr(kill_chain_phase, "phase_name")
    temp += ';'
    # kill_chain_phases_template(owner):
    temp += '$kcps (listed: $kcp{}, owner: ${}) isa kill_chain_phases;'.format(count, owner)
    return temp


# Add references templates
'''
created_by_ref sub relation,
    relates created,
    relates ref;

fun(source, tid)
'''
def created_by_ref_template(source, tid):
    match = ' $citarget isa identity, has id "' + tid + '";'
    insert = " (created: ${}, ref: $citarget) isa created_by_ref;".format(source)
    return match, insert


'''
object_marking_refs sub relation,
    relates marked,
    relates ref;
'''
def object_marking_ref_template(source, tids):
    matches = []
    inserts = []
    for tid in tids:
        matches.append(' $mdtarget isa marking-definition, has id "' + tid + '";')
        inserts.append(" (marked: ${}, ref: $mdtarget) isa object_marking_refs;".format(source))
    return matches, inserts


'''
x_mitre_modified_by_ref sub relation,
    relates modified,
    relates ref;
'''
def x_mitre_modified_by_ref_template(source, tid):
    match = ' $mitarget isa identity, has id "' + tid + '";'
    insert = " (modified: ${}, ref: $mitarget) isa x_mitre_modified_by_ref;".format(source)
    return match, insert


'''
tactic_refs sub relation,
    relates owner,
    relates listed;

tactics should be inserted before matrix

fun(matrix, tactic["id"])
'''
def tactic_refs_template(source, tids):
    matches = []
    inserts = []
    count = 0
    for tid in tids:
        matches.append(' $tactic{} isa tactic, has id "'.format(count) + tid + '";')
        inserts.append(' (owner: ${}, listed: $tactic{}) isa tactic_refs;'.format(source, count))
        count += 1
    return matches, inserts

## v2.1.0 update
'''
x_mitre_data_source_ref sub relation,
    relates component,
    relates ref;

data_source should be inserted before data_component

fun(data_component, data_source["id"])
'''
def x_mitre_data_source_ref_template(source, tid):
    match = ' $dstarget isa data_source, has id "{}";'.format(tid)
    insert = ' (component: ${}, ref: $dstarget) isa x_mitre_data_source_ref;'.format(source)
    return match, insert


def addCommonRefs(entity, variable):
    matches = []
    inserts = []
    # Add created_by_ref relation
    created_by_ref = entity.get("created_by_ref")
    if not created_by_ref:
        logging.error("{} does not have created_by_ref property".format(entity))
    else:
        tmp_match, tmp_insert = created_by_ref_template(variable, created_by_ref)
        matches.append(tmp_match)
        inserts.append(tmp_insert)

    # Add object_marking_refs relation
    object_marking_refs = entity.get("object_marking_refs")
    if not object_marking_refs:
        logging.error("{} does not have object_marking_refs property".format(entity))
    else:
        tmp_matches, tmp_inserts = object_marking_ref_template(variable, object_marking_refs)
        matches.extend(tmp_matches)
        inserts.extend(tmp_inserts)

    # Add x_mitre_modified_by_ref relation
    x_mitre_modified_by_ref = entity.get("x_mitre_modified_by_ref")
    if not x_mitre_modified_by_ref:
        logging.error("{} does not have x_mitre_modified_by_ref property".format(entity))
    else:
        tmp_match, tmp_insert = x_mitre_modified_by_ref_template(variable, x_mitre_modified_by_ref)
        matches.append(tmp_match)
        inserts.append(tmp_insert)

    return matches, inserts

###############################################
########### Add relations templates############
###############################################

'''
basic_rel sub relation,
    abstract,
    owns id @key,
    owns types,
    owns spec_version,
    owns created,
    owns modified,
    owns relationship_type,
    owns revoked,
    owns x_mitre_domains,
    owns x_mitre_version,
    owns description,
    owns x_mitre_deprecated,
    plays created_by_ref:created,
    plays object_marking_refs:marked,
    plays x_mitre_modified_by_ref:modified,
    plays external_references:owner,
    relates source_ref,
    relates target_ref;

output: , has id $id, ...,  has types $types
'''
def addRelatPpts(entity):
    temp = ''
    temp += addStr(entity, "id")
    temp += addStr(entity, "types")
    temp += addStr(entity, "spec_version")
    temp += addDate(entity, "created")
    temp += addDate(entity, "modified")
    temp += addStr(entity, "relationship_type")
    temp += addStr(entity, "revoked")
    temp += addStr(entity, "x_mitre_version")
    temp += addList(entity, "x_mitre_domains")
    temp += addStr(entity, "description")
    temp += addBool(entity, "x_mitre_deprecated")
    return temp + ';'

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

# relationships
def relationships_template(relation):
    matches = []
    inserts = []
    stype, sid, ttype, tid, rtype = parseRelationship(relation)

    matches.append(' $source isa {}, has id "{}";'.format(stype, sid))
    matches.append(' $target isa {}, has id "{}";'.format(ttype, tid))

    inserts.append(' $relat ({}: $source, {}: $target) isa {}'.format(RELATION_ACTORS_MAPPING[rtype][0],
                                                                RELATION_ACTORS_MAPPING[rtype][1],
                                                                rtype))
    inserts.append(addRelatPpts(relation))

    tmp_insert = ''
    count = 0
    external_references = relation.get("external_references", [])
    for external_reference in external_references:
        tmp_insert += external_reference_template(external_reference, "relat", count)
        count += 1

    inserts.append(tmp_insert)

    # Add common *_ref relations
    tmp_matches, tmp_inserts = addCommonRefs(relation, "relat")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)
    return matches, inserts

