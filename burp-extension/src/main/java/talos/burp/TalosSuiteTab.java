package talos.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Suite tab: engine → endpoint tree + spacious request table + viewers.
 * Live updates never steal tree or table selection.
 */
final class TalosSuiteTab extends JPanel implements TalosStore.Listener, TalosProjectSession.Listener {
    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final TalosStore store;
    private final TalosProjectSession session;
    private final JTree tree;
    private final RequestTableModel tableModel = new RequestTableModel();
    private final JTable table = new JTable(tableModel);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JComboBox<ProjectItem> projectCombo = new JComboBox<>();
    private final JLabel hint = new JLabel();
    private final JPanel banner = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
    private final JLabel bannerLabel = new JLabel();
    private final JButton switchButton = new JButton("Switch");
    private boolean updatingCombo;

    TalosSuiteTab(MontoyaApi api, TalosStore store, TalosProjectSession session) {
        super(new BorderLayout());
        this.store = store;
        this.session = session;
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        tree = new JTree(store.treeModel());
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setRowHeight(0);
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.addTreeSelectionListener(e -> onTreeSelection());

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getTableHeader().setReorderingAllowed(true);
        setColumnWidths();
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onTableSelection();
            }
        });
        applyBurpDisplayLook(api);

        JScrollPane treeScroll = new JScrollPane(tree);
        treeScroll.setBorder(BorderFactory.createEmptyBorder());
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        api.userInterface().applyThemeToComponent(treeScroll);
        api.userInterface().applyThemeToComponent(tableScroll);

        JSplitPane viewers = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(),
                responseEditor.uiComponent()
        );
        viewers.setResizeWeight(0.5);
        viewers.setBorder(BorderFactory.createEmptyBorder());

        JSplitPane right = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewers);
        right.setResizeWeight(0.42);
        right.setBorder(BorderFactory.createEmptyBorder());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, right);
        split.setResizeWeight(0.22);
        split.setBorder(BorderFactory.createEmptyBorder());
        split.setPreferredSize(new Dimension(1280, 760));

        add(buildNorth(api), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        api.userInterface().applyThemeToComponent(this);
        store.addListener(this);
        session.addListener(this);
        reloadProjects();
        refreshBanner();
        expandAll();
    }

    private JPanel buildNorth(MontoyaApi api) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBorder(BorderFactory.createEmptyBorder(2, 4, 0, 4));
        JLabel label = new JLabel("Talos project");
        projectCombo.setPrototypeDisplayValue(new ProjectItem("xxxxxxxx", "Select a project name here", 0));
        projectCombo.addActionListener(e -> onProjectChosen());
        JButton refresh = new JButton("Refresh");
        refresh.setToolTipText("Reload snapshots from ~/.talos/burp (also happens automatically)");
        refresh.addActionListener(e -> {
            String keepId = selectedRecordId();
            if (session.isBound()) {
                session.reloadBound();
            }
            reloadProjects();
            refreshRequestTable();
            if (keepId != null) {
                selectByRecordId(keepId);
            }
        });
        bar.add(label);
        bar.add(projectCombo);
        bar.add(refresh);
        bar.add(Box.createHorizontalStrut(8));
        bar.add(hint);

        switchButton.addActionListener(e -> session.switchToForeign());
        JButton ignore = new JButton("Ignore");
        ignore.addActionListener(e -> session.ignoreForeign());
        banner.add(bannerLabel);
        banner.add(switchButton);
        banner.add(ignore);
        banner.setVisible(false);

        JPanel north = new JPanel(new BorderLayout());
        north.add(bar, BorderLayout.NORTH);
        north.add(banner, BorderLayout.SOUTH);
        api.userInterface().applyThemeToComponent(north);
        api.userInterface().applyThemeToComponent(bar);
        api.userInterface().applyThemeToComponent(banner);
        api.userInterface().applyThemeToComponent(projectCombo);
        return north;
    }

    private void onProjectChosen() {
        if (updatingCombo) {
            return;
        }
        ProjectItem item = (ProjectItem) projectCombo.getSelectedItem();
        if (item == null || item.projectId.isEmpty()) {
            if (session.isBound()) {
                session.unbind();
            }
            return;
        }
        if (!item.projectId.equals(session.boundProjectId())) {
            session.bind(item.projectId, item.name);
        }
    }

    private void reloadProjects() {
        updatingCombo = true;
        try {
            projectCombo.removeAllItems();
            projectCombo.addItem(new ProjectItem("", "— none —", 0));
            String bound = session.boundProjectId();
            boolean seenBound = bound.isEmpty();
            for (TalosSnapshots.ProjectRef ref : TalosSnapshots.listProjects()) {
                projectCombo.addItem(new ProjectItem(ref.projectId, ref.name, ref.records));
                if (ref.projectId.equals(bound)) {
                    seenBound = true;
                }
            }
            if (!seenBound) {
                projectCombo.addItem(new ProjectItem(bound, session.boundProjectName(), 0));
            }
            selectBoundItem();
        } finally {
            updatingCombo = false;
        }
        refreshHint();
    }

    private void selectBoundItem() {
        String bound = session.boundProjectId();
        for (int i = 0; i < projectCombo.getItemCount(); i++) {
            ProjectItem item = projectCombo.getItemAt(i);
            if (item != null && item.projectId.equals(bound)) {
                projectCombo.setSelectedIndex(i);
                return;
            }
        }
        projectCombo.setSelectedIndex(0);
    }

    private void refreshHint() {
        if (!session.isBound()) {
            hint.setText("Select a project. The tree is empty until one is bound.");
        } else {
            hint.setText("Bound to this Burp project. Auto-refresh is on.");
        }
    }

    private void refreshBanner() {
        if (!session.hasForeign()) {
            banner.setVisible(false);
            return;
        }
        String foreign = session.foreignProjectName();
        if (session.isBound()) {
            bannerLabel.setText("Traffic from " + foreign
                    + " — this tab is bound to " + session.boundProjectName() + ".");
            switchButton.setText("Switch");
        } else {
            bannerLabel.setText("Traffic from " + foreign + ". Bind this Burp window to it?");
            switchButton.setText("Bind");
        }
        banner.setVisible(true);
    }

    @Override
    public void bindingChanged() {
        reloadProjects();
        refreshBanner();
        expandAll();
        tableModel.setRows(List.of());
    }

    @Override
    public void foreignChanged() {
        refreshBanner();
    }

    @Override
    public void snapshotChanged() {
        reloadProjects();
    }

    @Override
    public void storeReplaced() {
        expandAll();
        tableModel.setRows(List.of());
    }

    /**
     * Match Burp's suite UI (HTTP history, site map), not the request editor.
     * currentEditorFont() is monospaced and usually smaller — do not use it here.
     */
    private void applyBurpDisplayLook(MontoyaApi api) {
        api.userInterface().applyThemeToComponent(table);
        api.userInterface().applyThemeToComponent(tree);
        JTableHeader header = table.getTableHeader();
        if (header != null) {
            api.userInterface().applyThemeToComponent(header);
        }

        Font display = api.userInterface().currentDisplayFont();
        if (display == null) {
            Object uiFont = UIManager.get("Table.font");
            if (uiFont instanceof Font font) {
                display = font;
            }
        }
        if (display != null) {
            table.setFont(display);
            tree.setFont(display);
            if (header != null) {
                header.setFont(display);
            }
        }

        Font bodyFont = table.getFont();
        int rowHeight = table.getFontMetrics(bodyFont).getHeight() + 8;
        Object uiRow = UIManager.get("Table.rowHeight");
        if (uiRow instanceof Integer integer && integer > rowHeight) {
            rowHeight = integer;
        }
        table.setRowHeight(rowHeight);
        tree.setRowHeight(rowHeight);
    }

    private void setColumnWidths() {
        TableColumnModel columns = table.getColumnModel();
        columns.getColumn(0).setPreferredWidth(80);
        columns.getColumn(1).setPreferredWidth(80);
        columns.getColumn(2).setPreferredWidth(520);
        columns.getColumn(3).setPreferredWidth(70);
        columns.getColumn(4).setPreferredWidth(360);
    }

    private void onTreeSelection() {
        refreshRequestTable();
    }

    private void onTableSelection() {
        int view = table.getSelectedRow();
        if (view < 0) {
            return;
        }
        TalosStore.RequestRecord record = tableModel.rowAt(table.convertRowIndexToModel(view));
        if (record == null) {
            return;
        }
        showRecord(record);
    }

    private void showRecord(TalosStore.RequestRecord record) {
        requestEditor.setRequest(record.request);
        if (record.response != null) {
            responseEditor.setResponse(record.response);
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse());
        }
    }

    @Override
    public void storeUpdated(TalosStore.RequestRecord record, boolean responseOnly) {
        expandAll();
        TreePath selected = tree.getSelectionPath();
        if (selected == null) {
            return;
        }
        Object user = TalosStore.userObject((javax.swing.tree.TreeNode) selected.getLastPathComponent());
        boolean relevant = user == record.endpoint
                || (user instanceof TalosStore.EngineNode engine && engine.token.equals(record.trace.engine));
        if (!relevant) {
            return;
        }
        String keepId = selectedRecordId();
        refreshRequestTable();
        if (keepId != null) {
            selectByRecordId(keepId);
        }
        if (keepId != null && keepId.equals(record.recordId)) {
            showRecord(record);
        }
    }

    private void refreshRequestTable() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            tableModel.setRows(List.of());
            return;
        }
        Object user = TalosStore.userObject((javax.swing.tree.TreeNode) path.getLastPathComponent());
        tableModel.setRows(store.requestsFor(user));
    }

    private String selectedRecordId() {
        int view = table.getSelectedRow();
        if (view < 0) {
            return null;
        }
        TalosStore.RequestRecord current = tableModel.rowAt(table.convertRowIndexToModel(view));
        return current == null ? null : current.recordId;
    }

    private void selectByRecordId(String recordId) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            TalosStore.RequestRecord row = tableModel.rowAt(i);
            if (row != null && recordId.equals(row.recordId)) {
                int view = table.convertRowIndexToView(i);
                if (view >= 0) {
                    table.getSelectionModel().setSelectionInterval(view, view);
                }
                return;
            }
        }
    }

    private void expandAll() {
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) store.treeModel().getRoot();
        expand(root);
    }

    private void expand(DefaultMutableTreeNode node) {
        tree.expandPath(new TreePath(node.getPath()));
        for (int i = 0; i < node.getChildCount(); i++) {
            expand((DefaultMutableTreeNode) node.getChildAt(i));
        }
    }

    private static final class ProjectItem {
        final String projectId;
        final String name;
        final int records;

        ProjectItem(String projectId, String name, int records) {
            this.projectId = projectId == null ? "" : projectId;
            this.name = name == null || name.isBlank() ? this.projectId : name;
            this.records = records;
        }

        @Override
        public String toString() {
            if (projectId.isEmpty()) {
                return name;
            }
            String label = name.equals(projectId) ? projectId : name + " — " + projectId;
            if (records > 0) {
                return label + " (" + records + ")";
            }
            return label;
        }
    }

    private static final class RequestTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Time", "Method", "URL", "Status", "Detail"
        };

        private final List<TalosStore.RequestRecord> rows = new ArrayList<>();

        void setRows(List<TalosStore.RequestRecord> next) {
            rows.clear();
            rows.addAll(next);
            fireTableDataChanged();
        }

        TalosStore.RequestRecord rowAt(int index) {
            if (index < 0 || index >= rows.size()) {
                return null;
            }
            return rows.get(index);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TalosStore.RequestRecord row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> TIME.format(row.capturedAt);
                case 1 -> row.request.method();
                case 2 -> row.request.url();
                case 3 -> row.status == 0 ? "" : Integer.toString(row.status);
                case 4 -> row.trace.summary();
                default -> "";
            };
        }
    }
}
