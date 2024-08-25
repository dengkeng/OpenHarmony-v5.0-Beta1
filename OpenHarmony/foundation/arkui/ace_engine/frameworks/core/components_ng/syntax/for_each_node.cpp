/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "core/components_ng/syntax/for_each_node.h"

#include "base/log/ace_trace.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/pattern/list/list_item_pattern.h"
#include "core/pipeline/base/element_register.h"
#include "core/pipeline_ng/pipeline_context.h"

namespace OHOS::Ace::NG {
namespace {
void MakeNodeMapById(const std::list<RefPtr<UINode>>& nodes, const std::list<std::string>& ids,
    std::map<std::string, RefPtr<UINode>>& result)
{
    ACE_DCHECK(ids.size() == nodes.size());
    auto idsIter = ids.begin();
    auto nodeIter = nodes.begin();
    while (idsIter != ids.end() && nodeIter != nodes.end()) {
        result.emplace(*idsIter, *nodeIter);
        ++idsIter;
        ++nodeIter;
    }
}
} // namespace

RefPtr<ForEachNode> ForEachNode::GetOrCreateForEachNode(int32_t nodeId)
{
    auto node = ElementRegister::GetInstance()->GetSpecificItemById<ForEachNode>(nodeId);
    if (node) {
        return node;
    }
    node = MakeRefPtr<ForEachNode>(nodeId);
    ElementRegister::GetInstance()->AddUINode(node);
    return node;
}

RefPtr<ForEachNode> ForEachNode::GetOrCreateRepeatNode(int32_t nodeId)
{
    auto node = ForEachNode::GetOrCreateForEachNode(nodeId);
    if (node) {
        node->isThisRepeatNode_ = true;
    }
    return node;
}

void ForEachNode::CreateTempItems()
{
    std::swap(ids_, tempIds_);
    std::swap(ModifyChildren(), tempChildren_);

    // RepeatNode only
    if (isThisRepeatNode_) {
        tempChildrenOfRepeat_ = std::vector<RefPtr<UINode>>(tempChildren_.begin(), tempChildren_.end());
    }
}

// same as foundation/arkui/ace_engine/frameworks/core/components_part_upd/foreach/foreach_element.cpp.
void ForEachNode::CompareAndUpdateChildren()
{
    if (isThisRepeatNode_) {
        return;
    }

    // result of id gen function of most re-recent render
    // create a map for quicker find/search
    std::unordered_set<std::string> newIdsSet(ids_.begin(), ids_.end());

    // result of id gen function of previous render/re-render
    // create a map for quicker find/search
    std::unordered_set<std::string> oldIdsSet(tempIds_.begin(), tempIds_.end());

    // ForEachNode only includes children for newly created_ array items
    // it does not include children of array items that were rendered on a previous
    // render
    std::list<RefPtr<UINode>> additionalChildComps;
    auto& children = ModifyChildren();
    std::swap(additionalChildComps, children);

    // create map id -> Node
    // old children
    std::map<std::string, RefPtr<UINode>> oldNodeByIdMap;
    MakeNodeMapById(tempChildren_, tempIds_, oldNodeByIdMap);

    int32_t additionalChildIndex = 0;
    for (const auto& newId : ids_) {
        auto oldIdIt = oldIdsSet.find(newId);
        if (oldIdIt == oldIdsSet.end()) {
            // found a newly added ID
            // insert new child item.
            auto newCompsIter = additionalChildComps.begin();
            std::advance(newCompsIter, additionalChildIndex++);
            if (newCompsIter != additionalChildComps.end()) {
                // Call AddChild to execute AttachToMainTree of new child.
                // Allow adding default transition.
                AddChild(*newCompsIter, DEFAULT_NODE_SLOT, false, true);
                InitDragManager(*newCompsIter);
            }
        } else {
            auto iter = oldNodeByIdMap.find(newId);
            // the ID was used before, only need to update the child position.
            if (iter != oldNodeByIdMap.end() && iter->second) {
                AddChild(iter->second, DEFAULT_NODE_SLOT, true);
            }
            oldIdsSet.erase(oldIdIt);
        }
    }

    for (const auto& oldId : oldIdsSet) {
        auto iter = oldNodeByIdMap.find(oldId);
        if (iter != oldNodeByIdMap.end()) {
            // Adding silently, so that upon removal
            // node is a part the tree.
            // OnDetachFromMainTree to be called while node
            // still part of the tree, we need to find
            // position in the tab tab for the tab.
            AddChild(iter->second, DEFAULT_NODE_SLOT, true);
            // Remove and trigger all Detach callback.
            RemoveChild(iter->second, true);
        }
    }

    ACE_SCOPED_TRACE("ForEachNode::Update Id[%d] preIds[%zu] newIds[%zu] oldIdsSet[%zu] additionalChildComps[%zu]",
        GetId(), tempIds_.size(), ids_.size(), oldIdsSet.size(), additionalChildComps.size());

    if (IsOnMainTree()) {
        for (const auto& newChild : additionalChildComps) {
            newChild->AttachToMainTree(false, GetContext());
        }
    }

    tempChildren_.clear();

    if (auto frameNode = GetParentFrameNode()) {
        frameNode->ChildrenUpdatedFrom(0);
    }
}

void ForEachNode::FlushUpdateAndMarkDirty()
{
    if (ids_ == tempIds_ && !isThisRepeatNode_) {
        tempIds_.clear();
        return;
    }
    tempIds_.clear();
    // mark parent dirty to flush measure.
    MarkNeedSyncRenderTree(true);
    MarkNeedFrameFlushDirty(PROPERTY_UPDATE_MEASURE_SELF_AND_PARENT | PROPERTY_UPDATE_BY_CHILD_REQUEST);
}

// RepeatNode only
void ForEachNode::FinishRepeatRender(std::list<int32_t>& removedElmtId)
{
    ACE_SCOPED_TRACE("ForEachNode::FinishRepeatRender");

    // Required to build unordered_set of RefPtr<UINodes>
    struct Hash {
        size_t operator()(const RefPtr<UINode>& node) const
        {
            return node->GetId();
        }
    };

    // includes "newly-added" and "reused" children
    const auto& children = GetChildren();

    std::unordered_set<RefPtr<UINode>, Hash>
        newNodeSet(children.begin(), children.end());

    // remove "unused" children
    for (const auto& oldNode: tempChildrenOfRepeat_) {
        if (newNodeSet.find(oldNode) == newNodeSet.end()) {
            // Adding silently, so that upon removal node is a part the tree.
            AddChild(oldNode, DEFAULT_NODE_SLOT, true);
            // Remove and trigger all Detach callback.
            RemoveChild(oldNode, true);
            // Collect IDs of removed nodes starting from 'oldNode' (incl.)
            CollectRemovedChildren({ oldNode }, removedElmtId, false);
        }
    }

    tempChildren_.clear();
    tempChildrenOfRepeat_.clear();

    if (auto frameNode = GetParentFrameNode()) {
        frameNode->ChildrenUpdatedFrom(0);
    }

    LOGE("ForEachNode::FinishRepeatRender END");
}

// RepeatNode only
void ForEachNode::MoveChild(uint32_t fromIndex)
{
    // copy child from tempChildrenOfRepeat_[fromIndex] and append to children_
    if (fromIndex < tempChildrenOfRepeat_.size()) {
        auto& node = tempChildrenOfRepeat_.at(fromIndex);
        AddChild(node, DEFAULT_NODE_SLOT, true);
    }
}

void ForEachNode::SetOnMove(std::function<void(int32_t, int32_t)>&& onMove)
{
    if (onMove && !onMoveEvent_) {
        auto parentNode = GetParentFrameNode();
        if (parentNode) {
            InitAllChildrenDragManager(true);
        } else {
            auto piplineContext = PipelineContext::GetCurrentContext();
            CHECK_NULL_VOID(piplineContext);
            auto taskExecutor = piplineContext->GetTaskExecutor();
            CHECK_NULL_VOID(taskExecutor);
            taskExecutor->PostTask(
                [weak = WeakClaim(this)]() mutable {
                    auto forEach = weak.Upgrade();
                    CHECK_NULL_VOID(forEach);
                    forEach->InitAllChildrenDragManager(true);
                },
                TaskExecutor::TaskType::UI, "ArkUIInitAllChildrenDragManager");
        }
    } else if (!onMove && onMoveEvent_) {
        InitAllChildrenDragManager(false);
    }
    onMoveEvent_ = onMove;
}

void ForEachNode::MoveData(int32_t from, int32_t to)
{
    if (from == to) {
        return;
    }

    auto idIter = ids_.begin();
    std::advance(idIter, from);
    auto id = *idIter;
    ids_.erase(idIter);
    idIter = ids_.begin();
    std::advance(idIter, to);
    ids_.insert(idIter, id);

    auto& children = ModifyChildren();
    auto fromIter = children.begin();
    std::advance(fromIter, from);
    auto child = *fromIter;
    children.erase(fromIter);
    auto toIter = children.begin();
    std::advance(toIter, to);
    children.insert(toIter, child);
    MarkNeedSyncRenderTree(true);
    MarkNeedFrameFlushDirty(PROPERTY_UPDATE_MEASURE_SELF_AND_PARENT | PROPERTY_UPDATE_BY_CHILD_REQUEST);
}

RefPtr<FrameNode> ForEachNode::GetFrameNode(int32_t index)
{
    return AceType::DynamicCast<FrameNode>(GetFrameChildByIndex(index, false, false));
}

void ForEachNode::InitDragManager(const RefPtr<UINode>& child)
{
    CHECK_NULL_VOID(onMoveEvent_);
    CHECK_NULL_VOID(child);
    auto childNode = AceType::DynamicCast<FrameNode>(child->GetFrameChildByIndex(0, false));
    CHECK_NULL_VOID(childNode);
    auto parentNode = GetParentFrameNode();
    CHECK_NULL_VOID(parentNode);
    if (parentNode->GetTag() != V2::LIST_ETS_TAG) {
        return;
    }
    auto pattern = childNode->GetPattern<ListItemPattern>();
    CHECK_NULL_VOID(pattern);
    pattern->InitDragManager(AceType::Claim(this));
}

void ForEachNode::InitAllChildrenDragManager(bool init)
{
    auto parentNode = GetParentFrameNode();
    CHECK_NULL_VOID(parentNode);
    if (parentNode->GetTag() != V2::LIST_ETS_TAG) {
        onMoveEvent_ = nullptr;
        return;
    }
    const auto& children = GetChildren();
    for (const auto& child : children) {
        if (!child || (child->GetChildren().size() != 1)) {
            continue;
        }
        auto listItem = AceType::DynamicCast<FrameNode>(child->GetFirstChild());
        if (!listItem) {
            continue;
        }
        auto pattern = listItem->GetPattern<ListItemPattern>();
        if (!pattern) {
            continue;
        }
        if (init) {
            pattern->InitDragManager(AceType::Claim(this));
        } else {
            pattern->DeInitDragManager();
        }
    }
}
} // namespace OHOS::Ace::NG
