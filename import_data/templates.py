#! python3
# *_template functions definition
import sys, logging
sys.path.append("..")
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
        "x_mitre_version"
    ],
    type => types
'''
def identity_template(identity):
    temp = ' $identity isa identity, has id "' + identity["id"] + '"'
    temp += addStr(identity, "types")
    temp += addStr(identity, "name")
    temp += addStr(identity, "spec_version")
    temp += addDate(identity, "created")
    temp += addDate(identity, "modified")
    temp += addStr(identity, "x_mitre_version")
    temp += addList(identity, "x_mitre_domains")
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
        "x_mitre_deprecated"
    ],
    type => types
'''
def technique_template(technique):
    # Common properties
    temp = ' $technique isa technique, has id "' + technique["id"] + '"'
    temp += addStr(technique, "types")
    temp += addStr(technique, "name")
    temp += addStr(technique, "spec_version")
    temp += addDate(technique, "created")
    temp += addDate(technique, "modified")
    temp += addStr(technique, "x_mitre_version")
    temp += addList(technique, "x_mitre_domains")

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
        "x_mitre_deprecated"
    ],
    type => types
'''
def software_template(software):
    # Common properties
    temp = ' $software isa software, has id "' + software["id"] + '"'
    temp += addStr(software, "types")
    temp += addStr(software, "name")
    temp += addStr(software, "spec_version")
    temp += addDate(software, "created")
    temp += addDate(software, "modified")
    temp += addStr(software, "x_mitre_version")
    temp += addList(software, "x_mitre_domains")

    # Particular properties
    temp += addBool(software, "revoked")
    temp += addStr(software, "description")
    temp += addList(software, "x_mitre_platforms")
    temp += addList(software, "x_mitre_contributors")
    temp += addBool(software, "x_mitre_deprecated")
    temp += addList(software, "x_mitre_aliases")
    temp += addStr(software, "x_mitre_old_attack_id")
    temp += ';'

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
        "x_mitre_deprecated"
    ],
    type => types
'''
def groups_template(groups):
    # Common properties
    temp = ' $groups isa groups, has id "' + groups["id"] + '"'
    temp += addStr(groups, "types")
    temp += addStr(groups, "name")
    temp += addStr(groups, "spec_version")
    temp += addDate(groups, "created")
    temp += addDate(groups, "modified")
    temp += addStr(groups, "x_mitre_version")
    temp += addList(groups, "x_mitre_domains")

    # Particular properties
    temp += addBool(groups, "revoked")
    temp += addStr(groups, "description")
    temp += addList(groups, "x_mitre_contributors")
    temp += addBool(groups, "x_mitre_deprecated")
    temp += addList(groups, "aliases")
    temp += ';'

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
        "x_mitre_old_attack_id"
    ],
    type => types
'''
def mitigation_template(mitigation):
    # Common properties
    temp = ' $mitigation isa mitigation, has id "' + mitigation["id"] + '"'
    temp += addStr(mitigation, "types")
    temp += addStr(mitigation, "name")
    temp += addStr(mitigation, "spec_version")
    temp += addDate(mitigation, "created")
    temp += addDate(mitigation, "modified")
    temp += addStr(mitigation, "x_mitre_version")
    temp += addList(mitigation, "x_mitre_domains")

    # Particular properties
    temp += addBool(mitigation, "revoked")
    temp += addBool(mitigation, "x_mitre_deprecated")
    temp += addStr(mitigation, "x_mitre_old_attack_id")
    temp += ';'

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
        "x_mitre_version"
    ],
    type => types
'''
def tactic_template(tactic):
    # Common properties
    temp = ' $tactic isa tactic, has id "' + tactic["id"] + '"'
    temp += addStr(tactic, "types")
    temp += addStr(tactic, "name")
    temp += addStr(tactic, "spec_version")
    temp += addDate(tactic, "created")
    temp += addDate(tactic, "modified")
    temp += addStr(tactic, "x_mitre_version")
    temp += addList(tactic, "x_mitre_domains")

    # Particular properties
    temp += addStr(tactic, "x_mitre_shortname")
    temp += ';'
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
        "x_mitre_version"
    ],
    type => types
'''
def matrix_template(matrix):
    # Common properties
    temp = ' $matrix isa matrix, has id "' + matrix["id"] + '"'
    temp += addStr(matrix, "types")
    temp += addStr(matrix, "name")
    temp += addStr(matrix, "spec_version")
    temp += addDate(matrix, "created")
    temp += addDate(matrix, "modified")
    temp += addStr(matrix, "x_mitre_version")
    temp += addList(matrix, "x_mitre_domains")

    # Particular properties
    temp += addStr(matrix, "description")
    temp += ';'

    # Add tactic_refs
    tactic_refs = matrix.get("tactic_refs")
    matches, inserts = tactic_refs_template("matrix", tactic_refs)
    inserts.append(temp)

    # Add common refs
    tmp_matches, tmp_inserts = addCommonRefs(matrix, "matrix")
    matches.extend(tmp_matches)
    inserts.extend(tmp_inserts)

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
    match = ' $itarget isa identity, has id "' + tid + '";'
    insert = " (created: ${}, ref: $itarget) isa created_by_ref;".format(source)
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
    match = ' $itarget isa identity, has id "' + tid + '";'
    insert = " (modified: ${}, ref: $itarget) isa x_mitre_modified_by_ref;".format(source)
    return match, insert


'''
tactic_refs sub relation,
    relates owner,
    relates listed;

tactics should be inserted before matrix

fun(matrix["id"], tactic["id"])
'''
def tactic_refs_template(matrix, tids):
    matches = []
    inserts = []
    count = 0
    for tid in tids:
        matches.append(' $tactic{} isa tactic, has id "'.format(count) + tid + '";')
        inserts.append(' (owner: ${}, listed: $tactic{}) isa tactic_refs;'.format(matrix, count))
        count += 1
    return matches, inserts


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
def addCommonPpts(entity):
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
    inserts.append(addCommonPpts(relation))

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

